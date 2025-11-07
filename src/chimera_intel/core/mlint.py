"""
MLint Main Application & CLI
(Refactored with FastAPI for runtime ops, Kafka resilience, and batching)
"""

import typer
import asyncio
import logging
import json
import joblib 
import pandas as pd
from rich.console import Console
from rich.pretty import pprint
from datetime import datetime
import uuid
import signal
from typing import List
import hashlib
import hmac # <-- Task 8: For signature verification
import uvicorn # <-- Task 1 & 7: For running FastAPI
from fastapi import FastAPI, HTTPException # <-- Task 1 & 7

from prometheus_client import start_http_server, Counter, Gauge, Histogram # <-- Task 6: Added Histogram

# Import schemas and modules
from .schemas import Entity, EntityType, Transaction, SwiftMessage, Alert, RiskLevel, AnalystStatus, TransactionAnalysisResult, SwiftAnalysisResult
from .mlint_clients import RefinitivSanctionsClient, OpenCorporatesClient, ChainalysisClient, OpenSanctionsPepClient
from .mlint_intel import IntelligenceAggregator
from .mlint_graph import GraphAnalyzer
from .mlint_ai import (
    summarize_adverse_media_ai, 
    train_isolation_forest, 
    train_supervised_model
)
from .mlint_analysis import (
    analyze_transaction_risk, 
    analyze_swift_message, # Now async
    run_backtest
)
from .mlint_config import settings

# --- KAFKA and SWIFT (AMQP) Dependencies ---
try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    KafkaConsumer, KafkaProducer = None, None
try:
    import pika
except ImportError:
    pika = None

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Global State (for runtime model refresh) ---
ISO_FOREST_MODEL = None
XGB_MODEL = None

# --- Metrics (Task 6: Updated) ---
METRIC_TRANSACTIONS_PROCESSED = Counter('mlint_transactions_processed_total', 'Total transactions processed')
METRIC_ALERTS_GENERATED = Counter('mlint_alerts_generated_total', 'Total alerts generated', ['risk_level'])
METRIC_SWIFT_PROCESSED = Counter('mlint_swift_messages_processed_total', 'Total SWIFT messages processed')
METRIC_MESSAGES_TO_DLQ = Counter('mlint_messages_dlq_total', 'Total messages sent to DLQ', ['queue'])
METRIC_GRAPH_BATCH_TIME = Histogram('mlint_graph_batch_duration_seconds', 'Time to insert batch into graph')

# --- Audit Log ---
LAST_AUDIT_HASH = "0" * 64

# --- Kafka DLQ Producer (Task 4) ---
if KafkaProducer:
    try:
        dlq_producer = KafkaProducer(
            bootstrap_servers=settings.kafka_broker,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        log.info(f"Kafka DLQ Producer connected to {settings.kafka_broker}")
    except NoBrokersAvailable:
        log.error("Kafka DLQ Producer: No brokers available. DLQ will fall back to file.")
        dlq_producer = None
else:
    dlq_producer = None

# --- Main App & Services ---
cli_app = typer.Typer(help="MLint: AI-Powered AML & Intelligence Platform [CLI]")
api_app = FastAPI(title="MLint Runtime Service") # <-- Task 1: FastAPI App
console = Console()

def get_services():
    """Dependency-injection-style service factory."""
    sanctions_client = RefinitivSanctionsClient()
    ubo_client = OpenCorporatesClient()
    chain_client = ChainalysisClient()
    pep_client = OpenSanctionsPepClient()
    
    intel_aggregator = IntelligenceAggregator(
        sanctions_client=sanctions_client,
        ubo_client=ubo_client,
        chain_client=chain_client,
        pep_client=pep_client 
    )
    graph_analyzer = GraphAnalyzer()
    return intel_aggregator, graph_analyzer

# --- Task 1: Model Lifecycle Management ---
def load_models(force: bool = False):
    """Loads ML models from disk into global state."""
    global ISO_FOREST_MODEL, XGB_MODEL
    
    if (ISO_FOREST_MODEL and XGB_MODEL) and not force:
        log.info("Models already loaded. Skipping.")
        return
        
    log.info("Loading models from disk...")
    try:
        ISO_FOREST_MODEL = joblib.load(settings.iso_forest_model_path)
        log.info(f"Loaded IsolationForest model from {settings.iso_forest_model_path}")
    except FileNotFoundError:
        log.warning(f"No IsolationForest model found at {settings.iso_forest_model_path}.")
        ISO_FOREST_MODEL = None

    try:
        XGB_MODEL = joblib.load(settings.supervised_model_path)
        log.info(f"Loaded Supervised XGB model from {settings.supervised_model_path}")
    except FileNotFoundError:
        log.warning(f"No Supervised model found at {settings.supervised_model_path}.")
        XGB_MODEL = None

@api_app.post("/models/refresh", tags=["Admin"])
def refresh_models_endpoint():
    """API endpoint to reload models from disk at runtime."""
    try:
        load_models(force=True)
        return {"status": "success", "message": "Models reloaded from disk."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@cli_app.command(name="refresh-models")
def refresh_models_cli():
    """CLI command to reload models (if app is run via CLI)."""
    console.print("Refreshing models...")
    load_models(force=True)
    console.print("[green]Models reloaded.[/green]")

# --- Task 7: Health Check Endpoint ---
@api_app.get("/health", tags=["Monitoring"])
def get_health():
    """Health check for container orchestration."""
    # In a real app, you'd check Kafka, Redis connections
    from .mlint_analysis import redis_client # Import here to avoid circularity
    if not ISO_FOREST_MODEL:
        return {"status": "degraded", "message": "IsolationForest model not loaded."}
    try:
        if not redis_client or not redis_client.ping():
             return {"status": "degraded", "message": "Redis connection failed."}
    except Exception as e:
        return {"status": "degraded", "message": f"Redis connection error: {e}"}
    return {"status": "ok"}

# --- CLI Commands ---

@cli_app.command(name="analyze-entity")
def analyze_entity_command(
    name: str = typer.Argument(..., help="Name of the entity (person, company, wallet)"),
    entity_type: EntityType = typer.Option("Person", help="Type of entity"),
    jurisdiction: str = typer.Option(None, help="Jurisdiction (for companies)"),
    address: str = typer.Option(None, help="Wallet address (if any)")
):
    """Run a full intelligence workup on a single entity."""
    console.rule(f"[bold blue]Analyzing Entity: {name}[/bold blue]")
    
    entity = Entity(
        name=name,
        entity_type=entity_type,
        jurisdiction=jurisdiction,
        addresses=[address] if address else []
    )
    
    intel_aggregator, graph_analyzer = get_services()
    
    async def _main():
        try:
            intel_results = await intel_aggregator.gather_entity_intelligence(entity)
            graph_results = await graph_analyzer.analyze_entity_graph(entity.entity_id)
            
            console.print("\n[bold]Sanctions Hits:[/bold]")
            pprint(intel_results.get('sanctions', []))
            console.print("\n[bold]PEP Screening:[/bold]")
            pprint(intel_results.get('pep_screening', []))
            
            media_hits = intel_results.get('adverse_media', [])
            summary = await summarize_adverse_media_ai(media_hits)

            console.print("\n[bold]Adverse Media (AI Summary):[/bold]")
            console.print(f"[italic]{summary}[/italic]")
            console.print("\n[bold]Adverse Media (Classified Hits):[/bold]")
            pprint(media_hits)
            
            console.print("\n[bold]UBO Info:[/bold]")
            pprint(intel_results.get('ubo'))
            console.print("\n[bold]Chain Analytics:[/bold]")
            pprint(intel_results.get('chain_analytics', []))
            console.print("\n[bold]Graph Analytics:[/bold]")
            pprint(graph_results)
            _audit_log("entity_check", {"entity_name": name}, "analyst_user")
        finally:
            await graph_analyzer.close()
    
    asyncio.run(_main())


# --- Real-Time Monitor (Combined with FastAPI) ---

# Task 3: Graph batching config
TX_BATCH_SIZE = 100
TX_BATCH_TIMEOUT = 10.0 # seconds

async def _run_kafka_consumer(graph_analyzer: GraphAnalyzer, shutdown_event: asyncio.Event):
    """
    Blocking Kafka consumer loop.
    (Task 3: Batching, Task 4: Manual Offset Commit & DLQ Producer)
    """
    consumer = None
    try:
        consumer = KafkaConsumer(
            settings.kafka_topic,
            bootstrap_servers=settings.kafka_broker,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='earliest',
            group_id='mlint_analyst_group',
            enable_auto_commit=False # <-- Task 4: Disable auto-commit
        )
    except NoBrokersAvailable:
        log.critical(f"FATAL: Cannot connect to Kafka at {settings.kafka_broker}.")
        return
    
    log.info("Kafka consumer connected successfully.")
    tx_batch_buffer: List[Transaction] = []
    last_batch_time = datetime.now()

    try:
        while not shutdown_event.is_set():
            message_batch = consumer.poll(timeout_ms=1000)
            if not message_batch:
                # --- Task 3: Time-based batch flushing ---
                if tx_batch_buffer and (datetime.now() - last_batch_time).total_seconds() > TX_BATCH_TIMEOUT:
                    log.info(f"Flushing {len(tx_batch_buffer)} txs to graph (timeout).")
                    with METRIC_GRAPH_BATCH_TIME.time():
                        await graph_analyzer.add_transactions_batch(tx_batch_buffer)
                    tx_batch_buffer.clear()
                    last_batch_time = datetime.now()
                continue # Check shutdown_event again

            for tp, messages in message_batch.items():
                batch_offsets = {}
                for msg in messages:
                    if shutdown_event.is_set():
                        break
                    
                    tx_data = msg.value
                    log.info(f"Received transaction {tx_data.get('tx_id')} from Kafka.")
                    
                    try:
                        # --- Task 8: Signature Verification Placeholder ---
                        # _verify_message_signature(msg)
                        
                        METRIC_TRANSACTIONS_PROCESSED.inc()
                        
                        if "metadata" not in tx_data: tx_data["metadata"] = {}
                        tx_data["metadata"]["kafka_topic"] = msg.topic
                        tx = Transaction(**tx_data)
                        
                        analysis_result = await analyze_transaction_risk(
                            tx, ISO_FOREST_MODEL, XGB_MODEL, settings.feature_order
                        )
                        
                        if analysis_result and analysis_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                            _create_alert_from_result(analysis_result)
                        
                        # Add to graph batch
                        tx_batch_buffer.append(tx)

                    except Exception as e:
                        log.error(f"Failed to process transaction {tx_data.get('tx_id')}: {e}", exc_info=True)
                        _send_to_dlq(tx_data, settings.kafka_dlq_topic, "transaction") # <-- Task 4
                    
                    # --- Task 4: Mark offset for commit ---
                    batch_offsets[tp] = msg.offset + 1

                # --- Task 4: Manual Offset Commit (per partition) ---
                if batch_offsets:
                    consumer.commit({tp: offset for tp, offset in batch_offsets.items()})

                # --- Task 3: Size-based batch flushing ---
                if len(tx_batch_buffer) >= TX_BATCH_SIZE:
                    log.info(f"Flushing {len(tx_batch_buffer)} txs to graph (size).")
                    with METRIC_GRAPH_BATCH_TIME.time():
                        await graph_analyzer.add_transactions_batch(tx_batch_buffer)
                    tx_batch_buffer.clear()
                    last_batch_time = datetime.now()
                
                if shutdown_event.is_set():
                    break
            
    except Exception as e:
        if not shutdown_event.is_set():
             log.error(f"Error in Kafka consumer loop: {e}", exc_info=True)
    finally:
        # --- Graceful Shutdown ---
        log.info("Kafka consumer stopping...")
        if tx_batch_buffer:
            log.info(f"Flushing final {len(tx_batch_buffer)} txs to graph.")
            with METRIC_GRAPH_BATCH_TIME.time():
                await graph_analyzer.add_transactions_batch(tx_batch_buffer)
        if consumer:
            consumer.close()
        log.info("Kafka consumer stopped cleanly.")

async def _run_swift_consumer(shutdown_event: asyncio.Event):
    """
    Blocking AMQP (RabbitMQ) consumer loop.
    (Task 5: Updated to call async AI function)
    """
    connection = None
    try:
        connection = pika.BlockingConnection(pika.URLParameters(settings.swift_amqp_url))
        channel = connection.channel()
        channel.queue_declare(queue=settings.swift_queue, durable=True)
    except Exception as e:
        log.critical(f"FATAL: Cannot connect to AMQP at {settings.swift_amqp_url}. Error: {e}")
        return
        
    log.info("AMQP (SWIFT) consumer connected successfully.")

    def callback(ch, method, properties, body):
        try:
            # --- Setup event loop for async tasks in thread ---
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            swift_data = json.loads(body.decode('utf-8'))
            log.info(f"Received SWIFT {swift_data.get('mt_type')}")
            METRIC_SWIFT_PROCESSED.inc()
            
            msg = SwiftMessage(**swift_data)
            
            # --- Task 5: Call async analysis function ---
            swift_result = loop.run_until_complete(analyze_swift_message(msg))
            
            if swift_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                _create_alert_from_swift(msg, swift_result)
            
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            log.error(f"Failed to process SWIFT message: {e}", exc_info=True)
            _send_to_dlq(swift_data, f"{settings.swift_queue}_dlq", "swift") # Send to DLQ
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    channel.basic_consume(queue=settings.swift_queue, on_message_callback=callback)
    
    try:
        while not shutdown_event.is_set() and connection.is_open:
            connection.process_data_events(time_limit=1.0)
    finally:
        log.info("AMQP consumer stopping...")
        if channel and channel.is_open:
            channel.stop_consuming()
        if connection and connection.is_open:
            connection.close()
            log.info("AMQP connection closed cleanly.")


# --- Service Startup Logic ---
@api_app.on_event("startup")
async def startup_event():
    """On API startup, load models and start background consumers."""
    global ISO_FOREST_MODEL, XGB_MODEL
    
    # 1. Start Prometheus
    try:
        start_http_server(8001)
        log.info("Prometheus metrics server started on port 8001")
    except OSError as e:
        log.warning(f"Could not start Prometheus server (port 8001): {e}")
        
    # 2. Load Models
    load_models(force=True)
    
    # 3. Init Services
    graph_analyzer = GraphAnalyzer()
    
    # 4. Start Consumers in background
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    
    # Handle OS signals for graceful shutdown
    def _handle_signal(sig, frame):
        log.warning(f"Received signal {sig}. Initiating graceful shutdown...")
        shutdown_event.set()
        
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    
    loop.create_task(_run_kafka_consumer(graph_analyzer, shutdown_event))
    loop.create_task(_run_swift_consumer(shutdown_event))
    log.info("Background consumers started.")

@cli_app.command(name="train-models")
def train_models_command(
    feature_file: str = typer.Argument(..., help="Path to CSV/Parquet with features"),
    labeled_file: str = typer.Option(None, help="Path to CSV/Parquet with labeled data (for supervised)")
):
    """Train and save the models using config paths and feature order."""
    console.rule("[bold magenta]Training ML Models[/bold magenta]")
    load_models(force=True) # Ensure global models are loaded
    
    try:
        features_df = pd.read_csv(feature_file)
    except Exception as e:
        console.print(f"[bold red]Failed to load feature file: {e}[/bold red]")
        raise typer.Exit(1)

    console.print(f"Training IsolationForest on {len(features_df)} samples...")
    iso_forest = train_isolation_forest(features_df[settings.feature_order])
    joblib.dump(iso_forest, settings.iso_forest_model_path)
    console.print(f"[green]IsolationForest model saved to {settings.iso_forest_model_path}[/green]")

    if labeled_file:
        try:
            labeled_df = pd.read_csv(labeled_file)
            console.print(f"Training Supervised (XGBoost) on {len(labeled_df)} labeled samples...")
            xgb_model = train_supervised_model(labeled_df[settings.feature_order + ['is_true_positive']])
            if xgb_model:
                joblib.dump(xgb_model, settings.supervised_model_path)
                console.print(f"[green]XGBoost model saved to {settings.supervised_model_path}[/green]")
        except Exception as e:
            console.print(f"[bold red]Failed to train supervised model: {e}[/bold red]")
    else:
        console.print("No labeled data file provided. Skipping supervised model training.")


@cli_app.command(name="run-backtest")
def run_backtest_command(
    labeled_file: str = typer.Argument(..., help="Path to labeled CSV/Parquet for backtesting")
):
    """Run the backtesting and evaluation suite."""
    console.rule("[bold yellow]Running Backtest & Evaluation[/bold yellow]")
    load_models(force=True)
    
    if not ISO_FOREST_MODEL or not XGB_MODEL:
        console.print("[bold red]Both models must be trained to run backtest.[/bold red]")
        raise typer.Exit(1)
        
    try:
        labeled_df = pd.read_csv(labeled_file)
    except Exception as e:
        console.print(f"[bold red]Failed to load labeled file: {e}[/bold red]")
        raise typer.Exit(1)
        
    metrics = run_backtest(labeled_df, ISO_FOREST_MODEL, XGB_MODEL, settings.feature_order)
    
    console.print("\n[bold]Backtest Metrics:[/bold]")
    pprint(metrics)

@cli_app.command(name="run-realtime-monitor")
def run_realtime_monitor_command(
    host: str = typer.Option("0.0.0.0", help="Host to bind the API server to."),
    port: int = typer.Option(8000, help="Port to run the API server on.")
):
    """
    Run the real-time monitor and API service.
    """
    console.rule("[bold green]Starting MLint Real-Time Service...[/bold green]")
    uvicorn.run(f"{__name__}:api_app", host=host, port=port, reload=False)

# --- Helper Functions (Logging, Alerting) ---

def _create_alert_from_result(result: TransactionAnalysisResult):
    alert = Alert(
        tx_id=result.transaction.tx_id,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        reason=f"High-risk transaction (Supervised: {result.risk_score_supervised:.2f}, Unsupervised: {result.anomaly_score_unsupervised:.2f})",
        feature_snapshot=result.contributing_features,
        analyst_status=AnalystStatus.PENDING_REVIEW,
        tags=["transactional", result.risk_level.value]
    )
    _audit_log("alert_generated", alert.dict(), "system")
    _send_to_review_queue(alert)
    METRIC_ALERTS_GENERATED.labels(risk_level=alert.risk_level.value).inc()
    log.info(f"ALERT CREATED: {alert.alert_id} for TX {alert.tx_id}. Score: {alert.risk_score:.2f}")

def _create_alert_from_swift(msg: SwiftMessage, result: SwiftAnalysisResult):
    alert = Alert(
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        reason=f"High-risk SWIFT {msg.mt_type}: {', '.join(result.red_flags)}",
        feature_snapshot={"sender": msg.sender_bic, "receiver": msg.receiver_bic, "amount": msg.amount},
        analyst_status=AnalystStatus.PENDING_REVIEW,
        tags=["swift", "trade-based", result.risk_level.value]
    )
    _audit_log("alert_generated", alert.dict(), "system")
    _send_to_review_queue(alert)
    METRIC_ALERTS_GENERATED.labels(risk_level=alert.risk_level.value).inc()
    log.info(f"ALERT CREATED: {alert.alert_id} for SWIFT from {msg.sender_bic}. Score: {alert.risk_score:.2f}")

def _audit_log(action: str, data: dict, user: str):
    """
    Creates a new audit log entry with a chained hash.
    (Task 8: For real security, this hash should be stored immutably)
    """
    global LAST_AUDIT_HASH
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "user": user,
        "request_id": str(uuid.uuid4()),
        "data": data,
        "previous_hash": LAST_AUDIT_HASH
    }
    
    log_string = json.dumps(log_entry, sort_keys=True)
    current_hash = hashlib.sha256(log_string.encode('utf-8')).hexdigest()
    log_entry_with_hash = {**log_entry, "hash": current_hash}
    LAST_AUDIT_HASH = current_hash

    logging.getLogger("AUDIT").info(json.dumps(log_entry_with_hash))

def _send_to_review_queue(alert: Alert):
    # This should be a robust queue (Kafka, RabbitMQ), but file is ok for demo.
    log.info(f"Sending Alert {alert.alert_id} to review queue...")
    with open("review_queue.log", "a") as f:
        f.write(alert.json() + "\n")

# --- Task 4: Updated DLQ function ---
def _send_to_dlq(message: dict, topic: str, queue_name: str):
    """Sends a failed message to the Kafka DLQ."""
    log.warning(f"Sending message to DLQ topic: {topic}")
    METRIC_MESSAGES_TO_DLQ.labels(queue=queue_name).inc()
    
    if dlq_producer:
        try:
            dlq_producer.send(topic, value=message)
        except Exception as e:
            log.error(f"Failed to send message to Kafka DLQ: {e}")
            # Fallback to file
            with open(f"{topic}.dlq", "a") as f:
                f.write(json.dumps(message) + "\n")
    else:
        # Fallback to file if producer not available
        with open(f"{topic}.dlq", "a") as f:
            f.write(json.dumps(message) + "\n")

# --- Task 8: Security Placeholder ---
def _verify_message_signature(msg_body: bytes, signature: str) -> bool:
    """Verifies an HMAC-SHA256 signature."""
    expected_sig = hmac.new(
        settings.message_signature_secret.encode('utf-8'),
        msg_body,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        log.warning(f"Invalid message signature. Got {signature}, expected {expected_sig}")
        return False
    return True


if __name__ == "__main__":
    audit_handler = logging.FileHandler("audit.log")
    audit_handler.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger("AUDIT").addHandler(audit_handler)
    logging.getLogger("AUDIT").setLevel(logging.INFO)
    
    cli_app()