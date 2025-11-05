"""
MLINT Stream module.
Contains Kafka consumer logic for real-time transaction ingestion,
fast-path analysis, and graph insertion.
"""

import logging
import json
from kafka import KafkaConsumer, KafkaProducer

# Core project imports
from chimera_intel.core.schemas import Transaction
from chimera_intel.core.config_loader import API_KEYS

# MLINT package imports (updated to prefixed, flat structure)
from .mlint_analysis import get_jurisdiction_risk
from .mlint_graph import get_neo4j_driver, insert_transaction_to_neo4j

logger = logging.getLogger(__name__)


def run_kafka_consumer(console):
    """
    [MLINT 2.0] Connects to Kafka and processes transactions in real-time.
    
    This is a scalable pipeline:
    1. Consumes from KAFKA_TOPIC_TRANSACTIONS.
    2. Runs fast, synchronous checks (structuring, jurisdiction).
    3. Inserts transaction into Neo4j.
    4. Produces transaction ID to KAFKA_TOPIC_SCORING_JOBS for
       a separate, async worker pool to handle heavy risk scoring.
    """
    servers = API_KEYS.kafka_bootstrap_servers
    topic_in = API_KEYS.kafka_topic_transactions
    topic_out = API_KEYS.kafka_topic_scoring_jobs
    group = API_KEYS.kafka_consumer_group
    
    if not all([servers, topic_in, topic_out, group]):
        console.print("[bold red]Error: Kafka settings (KAFKA_BOOTSTRAP_SERVERS, etc.) not set.[/bold red]")
        return

    neo4j_driver = get_neo4j_driver()
    if not neo4j_driver:
        console.print("[bold red]Error: Neo4j credentials not set. Stream consumer cannot start.[/bold red]")
        return

    console.print(f"Connecting to Kafka at {servers}...")
    
    try:
        consumer = KafkaConsumer(
            topic_in,
            bootstrap_servers=servers.split(','),
            auto_offset_reset='earliest',
            group_id=group,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        producer = KafkaProducer(
            bootstrap_servers=servers.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
    except Exception as e:
        console.print(f"[bold red]Kafka connection error:[/bold red] {e}")
        logger.error(f"Kafka connection failed: {e}", exc_info=True)
        neo4j_driver.close()
        return

    console.print(f"Subscribing to topic '[bold cyan]{topic_in}[/bold cyan]'")
    console.print(f"Producing jobs to topic '[bold yellow]{topic_out}[/bold yellow]'")
    console.print("[italic]Press CTRL+C to stop...[/italic]")
    
    try:
        for message in consumer:
            tx_data = message.value
            console.print(f"\n[green]Received Transaction {tx_data.get('id')}[/green]")
            
            # 1. Validate Schema
            try:
                tx = Transaction.model_validate(tx_data)
            except Exception as e:
                console.print(f"[red]Invalid transaction schema: {e}[/red]"); continue
            
            # 2. Run Sync Risk Checks (Fast, In-Memory)
            alerts = []
            if get_jurisdiction_risk(tx.sender_jurisdiction).risk_score > 50 or \
               get_jurisdiction_risk(tx.receiver_jurisdiction).risk_score > 50:
                alerts.append("High-Risk Jurisdiction")
            
            if 8000 < tx.amount < 10000:
                alerts.append("Potential Structuring")
            
            # 3. Push to Graph DB (Fast, Idempotent)
            insert_transaction_to_neo4j(neo4j_driver, tx)
            
            # 4. Produce job for Async Scoring
            job_payload = {"tx_id": tx.id, "sender_id": tx.sender_id, "receiver_id": tx.receiver_id}
            producer.send(topic_out, value=job_payload)
            producer.flush() # Ensure it sends
            
            console.print(f"  -> Processed & Inserted: {tx.sender_id} -> {tx.receiver_id}")
            console.print(f"  -> [cyan]Published job {tx.id} to '{topic_out}' for async scoring.[/cyan]")
            if alerts:
                console.print(f"  [bold yellow]Sync Alerts:[/bold] {', '.join(alerts)}")

    except KeyboardInterrupt:
        console.print("\nShutting down Kafka consumer...")
    except Exception as e:
        console.print(f"[bold red]Kafka Error:[/bold red] {e}")
        logger.error(f"Kafka consumer failed: {e}", exc_info=True)
    finally:
        consumer.close()
        producer.close()
        neo4j_driver.close()