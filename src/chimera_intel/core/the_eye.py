"""
🧿 THE EYE — OSINT Corporate Intelligence Platform
Codename: "The Eye"
Role: Central AI intelligence, orchestrator, and data analyzer of the full OSINT ecosystem.
Core Principle: “If The Eye cannot find it — it does not exist on the Internet.”
"""

import asyncio
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field

# --- Core Chimera Imports ---
from chimera_intel.core.config_loader import ConfigLoader
from chimera_intel.core.logger_config import setup_logging
from chimera_intel.core.plugin_manager import PluginManager
from chimera_intel.core.graph_db import GraphDB
from chimera_intel.core.gemini_client import GeminiClient
from chimera_intel.core.reporter import Reporter
from chimera_intel.core.plugin_interface import ChimeraPlugin

# --- Logical Extension Imports (from your project) ---
# 1. Data Processing & Validation
from chimera_intel.core.entity_resolver import EntityResolver
from chimera_intel.core.counter_intelligence import CounterIntelligence
from chimera_intel.core.honeypot_detector import HoneypotDetector
from chimera_intel.core.credibility_assessor import CredibilityAssessor
from chimera_intel.core.ethical_guardrails import EthicalGuardrails
from chimera_intel.core.source_trust_model import SourceTrustModel

# 2. Strategic & Tasking Logic
from chimera_intel.core.strategist import Strategist
from chimera_intel.core.source_triage import SourceTriage

# 3. Core Graph & Data Analytics
from chimera_intel.core.graph_analyzer import GraphAnalyzer
from chimera_intel.core.correlation_engine import CorrelationEngine
from chimera_intel.core.temporal_analyzer import TemporalAnalyzer

# 4. Narrative & Sentiment Analysis
from chimera_intel.core.topic_clusterer import TopicClusterer
from chimera_intel.core.narrative_analyzer import NarrativeAnalyzer
from chimera_intel.core.disinformation_analyzer import DisinformationAnalyzer
from chimera_intel.core.cultural_sentiment import CulturalSentiment

# 5. Risk & Predictive Analysis
from chimera_intel.core.risk_assessment import RiskAssessment
from chimera_intel.core.opsec_analyzer import OpsecAnalyzer
from chimera_intel.core.wargaming_engine import WargamingEngine
from chimera_intel.core.attack_path_simulator import AttackPathSimulator
from chimera_intel.core.alternative_hypothesis_generator import AlternativeHypothesisGenerator
from chimera_intel.core.strategic_forecaster import StrategicForecaster

# 6. Self-Learning & Reporting
from chimera_intel.core.metacognition import Metacognition
from chimera_intel.core.grapher_3d import Grapher3D

# Setup logger
setup_logging()
logger = logging.getLogger("chimera_intel.the_eye")

THE_EYE_BANNER = r"""
         ________
       .-'        `-.
      .'             `.
     /     .----.      \
    |    /   o   \     |
    |   |    ●    |    |
    |    \   o   /     |
     \     `----'      /
      `.             .'
        `-.________.-'
    
    🧿 THE EYE - OSINT Corporate Intelligence Platform
    "If The Eye cannot find it — it does not exist on the Internet."
"""

# --- Data Schemas (as defined in your spec) ---

class DiscoveryLink(BaseModel):
    target_id: str
    relation: str
    evidence: str

class DiscoveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identifier: str
    source: str
    type: str
    value: Any
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    links: List[DiscoveryLink] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: Set[str] = Field(default_factory=set)

class SystemHealthReport(BaseModel):
    """Data model for the AI agent's validation checklist."""
    banner_displayed: bool = False
    api_connections_alive: bool = False
    api_quota_status: str = "unknown" # NEW: Refinement 4
    osint_modules_loaded: int = 0
    database_connection: str = "disconnected"
    cache_connection: str = "disconnected" # NEW: Refinement 4
    config_schema_version: str = "mismatch" # NEW: Refinement 4
    threads_running: int = 0 # (Still a placeholder, needs dynamic monitor)
    pii_detected: List[str] = Field(default_factory=list)
    legal_compliance: str = "not_passed"
    errors_in_last_run: List[str] = Field(default_factory=list)
    healthy: bool = False
    remediation_steps: List[str] = Field(default_factory=list)

class FullAnalysisReport(BaseModel):
    """Holds all computed logic before AI summary and final report."""
    metrics: Dict[str, Any] = Field(default_factory=dict)
    graph_analytics: Dict[str, Any] = Field(default_factory=dict)
    narrative_analysis: Dict[str, Any] = Field(default_factory=dict)
    predictive_analysis: Dict[str, Any] = Field(default_factory=dict)
    exposure_score: float = 0.0
    pii_found: List[str] = Field(default_factory=list)
    ai_summary: str = ""
    run_statistics: Dict[str, Any] = Field(default_factory=dict)


class TheEye:
    """
    Implements the central OSINT orchestrator and analyzer, "The Eye".
    """

    def __init__(self):
        """
        --- Component 1: Initialization Layer ---
        """
        logger.info("Initializing 🧿 The Eye...")
        self.config_loader = ConfigLoader()
        self.config = self.config_loader.load_config()
        
        # --- Load Core Components ---
        self.plugin_manager = PluginManager(plugin_dir="plugins")
        self.graph_db = GraphDB()
        self.gemini_client = GeminiClient()
        self.reporter = Reporter()
        self.guardrails = EthicalGuardrails()

        # Load OSINT source plugins
        self.osint_plugins: List[ChimeraPlugin] = self.plugin_manager.load_plugins()
        logger.info(f"Loaded {len(self.osint_plugins)} OSINT source plugins.")

        # --- Data Stores ---
        self.entities: Dict[str, DiscoveryRecord] = {}
        self.relations: List[Dict[str, Any]] = []
        self.discovered_identifiers: Set[str] = set()
        self.raw_text_corpus: List[str] = []
        self.low_confidence_log: List[Dict[str, Any]] = []
        
        # --- Health & Analytics ---
        self.health_report = SystemHealthReport()
        self.final_analysis = FullAnalysisReport()
        
        # --- NEW: Refinement 2 (Attribute Guard) ---
        self.initial_identifier: Optional[str] = None
        
        # --- NEW: Refinement 3 (Parallelism Control) ---
        self.discovery_semaphore = asyncio.Semaphore(10) # Control concurrency

        # --- Instantiate All Logical Engines ---
        # (Assuming all these modules exist in core as per the file list)
        self.entity_resolver = EntityResolver(self.entities)
        self.credibility_assessor = CredibilityAssessor()
        self.honeypot_detector = HoneypotDetector()
        self.counter_intelligence = CounterIntelligence()
        self.source_trust_model = SourceTrustModel()
        self.strategist = Strategist()
        self.source_triage = SourceTriage(self.source_trust_model)
        self.graph_analyzer = GraphAnalyzer(self.graph_db)
        self.correlation_engine = CorrelationEngine(self.graph_db)
        self.temporal_analyzer = TemporalAnalyzer()
        self.topic_clusterer = TopicClusterer()
        self.narrative_analyzer = NarrativeAnalyzer()
        self.disinformation_analyzer = DisinformationAnalyzer()
        self.cultural_sentiment = CulturalSentiment()
        self.risk_assessment = RiskAssessment()
        self.opsec_analyzer = OpsecAnalyzer()
        self.wargaming_engine = WargamingEngine()
        self.attack_path_simulator = AttackPathSimulator(self.graph_db)
        self.alternative_hypothesis_gen = AlternativeHypothesisGenerator()
        self.forecaster = StrategicForecaster()
        self.metacognition = Metacognition()
        self.grapher_3d = Grapher3D()

    # --- 1. System Health Check ---

    def check_cache_health(self) -> str:
        """Mock check for cache connection."""
        # TODO: Replace with real cache health check (e.g., Redis ping)
        try:
            # e.g., self.redis_client.ping()
            return "ok"
        except Exception:
            return "disconnected"

    def check_system_health(self) -> SystemHealthReport:
        """
        AI agent validation checklist.
        NEW: Expanded with Refinement 4.
        """
        report = SystemHealthReport()
        report.banner_displayed = True
        
        # Check APIs
        try:
            if self.gemini_client.is_configured():
                report.api_connections_alive = True
                # NEW: Check quota (assuming method exists)
                # report.api_quota_status = self.gemini_client.check_quota()
                report.api_quota_status = "ok" # Placeholder
            else:
                report.remediation_steps.append("Check Gemini/OpenAI API key.")
        except Exception as e:
            logger.warning(f"API health check failed: {e}")
            report.errors_in_last_run.append(f"API check error: {e}")

        # Check OSINT modules
        report.osint_modules_loaded = len(self.osint_plugins)
        if report.osint_modules_loaded == 0:
            report.remediation_steps.append("No OSINT plugins found.")
            
        # Check DB
        if self.graph_db.is_connected():
            report.database_connection = "ok"
        else:
            report.database_connection = "disconnected"
            report.remediation_steps.append("GraphDB is not connected.")
            
        # NEW: Check Cache
        report.cache_connection = self.check_cache_health()
        if report.cache_connection != "ok":
            report.remediation_steps.append("Cache (Redis) is not connected.")
            
        # NEW: Check Config Version (mocked)
        # config_version = self.config_loader.get_version()
        config_version = "1.0" # Placeholder
        if config_version == "1.0":
            report.config_schema_version = "ok"
        else:
            report.remediation_steps.append("Config schema mismatch.")
        
        # Check compliance
        if self.guardrails.is_enabled():
            report.legal_compliance = "passed"
        else:
            report.remediation_steps.append("Ethical Guardrails are not enabled.")

        # Final health status
        report.healthy = all([
            report.api_connections_alive,
            report.osint_modules_loaded > 0,
            report.database_connection == "ok",
            report.cache_connection == "ok",
            report.config_schema_version == "ok",
            report.legal_compliance == "passed"
        ])
        
        self.health_report = report
        if not report.healthy:
            logger.error(f"System health check: FAILED. Remediation: {report.remediation_steps}")
        else:
            logger.info("System health check: PASSED")
        return report

    # --- 2. Data Ingestion & Processing Pipeline ---
    
    async def start_discovery_thread(self, identifier: str, entity_type: Optional[str] = None):
        """
        Runs a *strategic* set of OSINT plugins against a single identifier.
        NEW: Uses asyncio.Semaphore for concurrency control (Refinement 3).
        """
        logger.info(f"Starting discovery thread for: {identifier} (Type: {entity_type})")
        
        # Strategic Task Prioritization
        plan = self.strategist.get_plan(identifier, entity_type, list(self.entities.values()))
        plugins_to_run = self.source_triage.get_prioritized_plugins(
            plan, 
            self.osint_plugins
        )
        logger.debug(f"Strategist selected {len(plugins_to_run)} plugins for {identifier}.")
        
        # --- NEW: Helper task for semaphore ---
        async def _discover_task(plugin: ChimeraPlugin, identifier: str):
            """Helper to wrap discovery with semaphore."""
            async with self.discovery_semaphore:
                logger.debug(f"[{identifier}] Running plugin: {plugin.name}")
                return await plugin.discover(identifier)

        tasks = []
        for plugin in plugins_to_run:
            try:
                tasks.append(_discover_task(plugin, identifier))
            except Exception as e:
                logger.error(f"Failed to create task for plugin {plugin.name}: {e}")
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, Exception):
                logger.warning(f"Plugin discovery failed: {res}")
            elif isinstance(res, DiscoveryRecord):
                await self.process_discovery(res)
            elif isinstance(res, list):
                for item in res:
                    if isinstance(item, DiscoveryRecord):
                        await self.process_discovery(item)

    async def process_discovery(self, record: DiscoveryRecord):
        """
        The main data processing pipeline for every new piece of data.
        """
        # 1. Compliance Check
        if not self.guardrails.validate_record(record):
            logger.warning(f"Skipping record {record.identifier} (Source: {record.source}) due to compliance failure.")
            return

        # 2. Counter-Intelligence & Credibility
        record = self.counter_intelligence.analyze(record)
        record.confidence = self.credibility_assessor.assess(record)
        if self.honeypot_detector.is_honeypot(record):
            record.tags.add("honeypot")
            record.confidence = 0.1
            logger.warning(f"Honeypot detected: {record.identifier}")

        # 3. Low-Confidence Logging
        if record.confidence < 0.2:
            logger.info(f"Logging low-confidence record, will not graph: {record.identifier} (Score: {record.confidence})")
            self.low_confidence_log.append({
                "identifier": record.identifier,
                "type": record.type,
                "source": record.source,
                "confidence": record.confidence,
                "timestamp": record.timestamp.isoformat()
            })
            return # Stop processing

        # 4. Entity Resolution
        existing_entity_id = self.entity_resolver.resolve(record)
        if existing_entity_id:
            self.entity_resolver.merge(existing_entity_id, record)
            updated_record = self.entities[existing_entity_id]
            self.graph_db.update_node_properties(
                existing_entity_id,
                {"confidence": updated_record.confidence, "metadata": updated_record.metadata}
            )
            return

        # 5. Graph Builder
        logger.info(f"Adding new entity to graph: {record.type} -> {record.identifier}")
        self.entities[record.id] = record
        self.graph_db.add_node(
            node_id=record.id,
            label=record.type,
            properties=record.model_dump()
        )
        for link in record.links:
            if link.target_id in self.entities:
                self.graph_db.add_edge(
                    source_id=record.id,
                    target_id=link.target_id,
                    label=link.relation.upper(),
                    properties={"evidence": link.evidence, "timestamp": record.timestamp}
                )
                self.relations.append({ "source": record.id, "target": link.target_id, "relation": link.relation })

        # 6. Recursive Discovery (Threaded Discovery)
        if (
            record.type in ("domain", "email", "organization", "person", "ip_address", "wallet") and
            record.identifier not in self.discovered_identifiers
        ):
            self.discovered_identifiers.add(record.identifier)
            logger.info(f"Recursive discovery triggered for: {record.identifier}")
            asyncio.create_task(self.start_discovery_thread(record.identifier, record.type))

    # --- 3. Core Analytical Layers ---

    def _normalize(self, value: float, max_value: float) -> float:
        """Helper to normalize a value between 0 and 1."""
        if max_value == 0:
            return 0.0
        return max(0.0, min(1.0, value / max_value))

    def calculate_exposure_score(self) -> float:
        """
        Runs a detailed, normalized formula to calculate exposure.
        NEW: Rebuilt based on Refinement 5.
        """
        logger.info("Calculating normalized exposure score...")
        try:
            entity_list = list(self.entities.values())
            opsec_findings = self.opsec_analyzer.analyze(entity_list)
            risk_data = self.risk_assessment.assess(entity_list)
            
            # --- Get factors (assuming Risk/Opsec modules provide these) ---
            # (Using placeholders for what modules would return)
            pii_count = risk_data.get('pii_count', 0)
            leak_count = risk_data.get('credential_leaks', 0)
            public_asset_count = opsec_findings.get('public_buckets', 0) + opsec_findings.get('public_repos', 0)
            connectivity = self.final_analysis.metrics.get('edge_count', 0) / (self.final_analysis.metrics.get('node_count', 1) or 1)

            # --- Normalize factors (on a 0-1 scale) ---
            # Max values are estimates, should be tuned
            normalized_pii_exposure = self._normalize(pii_count, 50) # 50 PII items = 1.0
            credential_leak_factor = self._normalize(leak_count, 10) # 10 leaks = 1.0
            opsec_public_asset_factor = self._normalize(public_asset_count, 20) # 20 public assets = 1.0
            graph_connectivity_factor = self._normalize(connectivity, 5) # Avg 5 relations/node = 1.0
            
            # --- Apply weighted formula ---
            score = (
                (0.3 * normalized_pii_exposure) +
                (0.3 * credential_leak_factor) +
                (0.2 * opsec_public_asset_factor) +
                (0.2 * graph_connectivity_factor)
            ) * 100
            
            return max(0.0, min(100.0, score)) # Cap to [0, 100]

        except Exception as e:
            logger.error(f"Failed to calculate exposure score: {e}")
            return 0.0 # Default to 0 on failure

    async def perform_graph_analytics(self):
        """Runs deep graph analysis *before* the AI summary."""
        logger.info("Performing deep graph analytics...")
        try:
            self.final_analysis.graph_analytics = {
                "clusters": self.graph_analyzer.find_communities(),
                "centrality": self.graph_analyzer.get_centrality(),
                "correlations": self.correlation_engine.find_correlations(list(self.entities.values())),
                "temporal_trends": self.temporal_analyzer.analyze_activity(list(self.entities.values()))
            }
        except Exception as e:
            logger.error(f"Graph analytics failed: {e}")

    async def perform_narrative_analysis(self):
        """Analyzes the public narrative and discourse."""
        logger.info("Performing narrative analysis...")
        if not self.raw_text_corpus:
            logger.info("No text corpus found, skipping narrative analysis.")
            return
        try:
            topics = self.topic_clusterer.cluster(self.raw_text_corpus)
            self.final_analysis.narrative_analysis = {
                "topics": topics,
                "narratives": self.narrative_analyzer.analyze(topics),
                "disinformation_flags": self.disinformation_analyzer.detect(topics),
                "overall_sentiment": self.cultural_sentiment.analyze(self.raw_text_corpus)
            }
        except Exception as e:
            logger.error(f"Narrative analysis failed: {e}")

    async def perform_predictive_analysis(self):
        """Runs wargaming, simulation, and forecasting."""
        logger.info("Performing predictive analysis...")
        try:
            attack_paths = self.attack_path_simulator.find_paths(self.initial_identifier)
            self.final_analysis.predictive_analysis = {
                "attack_paths": attack_paths,
                "wargame_scenarios": self.wargaming_engine.run_simulations(attack_paths),
                "alternative_hypotheses": self.alternative_hypothesis_gen.generate(list(self.entities.values()), self.final_analysis.graph_analytics),
                "strategic_forecast": self.forecaster.generate_forecast(list(self.entities.values()))
            }
        except Exception as e:
            logger.error(f"Predictive analysis failed: {e}")

    async def perform_ai_analysis(self):
        """The final AI reasoning step, synthesizing all pre-computed analytics."""
        logger.info("Performing final AI analysis...")
        
        self.final_analysis.pii_found = [e.identifier for e in self.entities.values() if e.type in ('email', 'phone', 'person', 'credential')]
        self.final_analysis.exposure_score = self.calculate_exposure_score()

        prompt = f"""
        You are "The Eye's" central intelligence. Analyze this full, pre-computed OSINT report.
        
        --- Target ---
        Primary Target: {self.initial_identifier}

        --- Key Metrics ---
        - Entities Found: {self.final_analysis.metrics.get('node_count', 0)}
        - Relations Found: {self.final_analysis.metrics.get('edge_count', 0)}
        - PII Entities: {len(self.final_analysis.pii_found)}
        - **Calculated Exposure Score: {self.final_analysis.exposure_score:.0f}/100**
        - Low-Confidence Items Logged: {len(self.low_confidence_log)}

        --- 1. Graph Analysis (Pre-computed) ---
        {self.final_analysis.graph_analytics}
        
        --- 2. Narrative Analysis (Pre-computed) ---
        {self.final_analysis.narrative_analysis}

        --- 3. Predictive Analysis (Pre-computed) ---
        {self.final_analysis.predictive_analysis}

        --- Your Task ---
        Based *only* on the data above, generate the following:
        
        1.  **Executive Summary**: A 3-paragraph "so what" summary.
        2.  **Key Findings & Anomalies**: 5-7 bullet points of the most critical or unusual findings.
        3.  **Prioritized Risks & Attack Paths**: Top 3-5 immediate risks.
        4.  **Intelligence Gaps & Next Steps**: What is missing? What are the next steps?
        """
        
        try:
            self.final_analysis.ai_summary = await self.gemini_client.generate_text(prompt)
        except Exception as e:
            logger.error(f"AI summary generation failed: {e}")
            self.final_analysis.ai_summary = "AI analysis failed to run."

    # --- 4. Reporting & Metacognition ---

    async def generate_report(self) -> Dict[str, str]:
        """
        Generates the final Deep Intelligence Report.
        NEW: Returns dict with PDF and JSON paths (Refinement 6).
        """
        logger.info("Generating Deep Intelligence Report...")
        
        # Generate 2D/3D graphs
        graph_2d_path, graph_3d_path = None, None
        try:
            graph_2d_path = self.graph_db.export_graph_visualization(format="png", filename="the_eye_2d_graph")
        except Exception as e: logger.error(f"Failed to generate 2D graph: {e}")
        try:
            graph_3d_path = self.grapher_3d.generate_3d_graph(nodes=self.entities.values(), edges=self.relations, filename="the_eye_3d_graph")
        except Exception as e: logger.error(f"Failed to generate 3D graph: {e}")
            
        # Compile report data
        report_data = {
            "title": f"The Eye: Deep Intelligence Report for {self.initial_identifier}",
            "banner": THE_EYE_BANNER,
            "timestamp": datetime.utcnow().isoformat(),
            "health_report": self.health_report.model_dump(),
            "analysis": self.final_analysis.model_dump(),
            "low_confidence_log": self.low_confidence_log,
            "visualizations": {"graph_2d_path": graph_2d_path, "graph_3d_path": graph_3d_path}
        }
        
        # Generate PDF
        pdf_path = ""
        try:
            pdf_path = self.reporter.generate_pdf(report_data, "the_eye_report")
            logger.info(f"Report generated: {pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")

        # NEW: Generate JSON
        json_path = ""
        try:
            # Assuming reporter.export_json(data, filename_base) exists
            json_path = self.reporter.export_json(report_data, "the_eye_report")
            logger.info(f"JSON export generated: {json_path}")
        except Exception as e:
            logger.error(f"Failed to export JSON report: {e}")

        return {"pdf": pdf_path, "json": json_path}

    async def perform_metacognitive_review(self):
        """Learns from its own performance to improve future runs."""
        logger.info("Performing metacognitive review...")
        try:
            run_stats = {
                "total_entities": len(self.entities),
                "total_relations": len(self.relations),
                "plugins_run_count": len(self.plugin_manager.get_plugins_run_stats()), # Assumes method exists
                "low_confidence_items": len(self.low_confidence_log)
            }
            self.final_analysis.run_statistics = run_stats
            
            lessons_learned = self.metacognition.analyze_run(run_stats, list(self.entities.values()))
            self.source_trust_model.update_from_lessons(lessons_learned)
            logger.info("Source trust model updated.")
        except Exception as e:
            logger.error(f"Metacognitive review failed: {e}")

    # --- 5. Run Archiving ---
    
    async def save_run_to_db(self):
        """Saves a summary of this investigation run to the graph database."""
        logger.info("Archiving investigation run to database...")
        run_id = f"run-{uuid.uuid4()}"
        run_properties = {
            "run_id": run_id,
            "target_identifier": self.initial_identifier,
            "timestamp": datetime.utcnow().isoformat(),
            "total_entities": self.final_analysis.metrics.get('node_count', 0),
            "total_relations": self.final_analysis.metrics.get('edge_count', 0),
            "exposure_score": self.final_analysis.exposure_score,
            "pii_found_count": len(self.final_analysis.pii_found),
            "low_confidence_items": len(self.low_confidence_log),
            "ai_summary": self.final_analysis.ai_summary
        }
        try:
            self.graph_db.add_node(node_id=run_id, label="InvestigationRun", properties=run_properties)
            logger.info(f"Successfully archived run {run_id}")
        except Exception as e:
            logger.error(f"Failed to archive investigation run to database: {e}")

    # --- 6. Main Orchestrator ---

    async def run(self, identifier: str):
        """
        Main entry point and orchestrator for "The Eye".
        """
        print(THE_EYE_BANNER)
        self.initial_identifier = identifier
        self.discovered_identifiers.add(identifier)
        
        # 1. Initialization Layer
        if not self.check_system_health().healthy:
            logger.error("The Eye cannot run. System is UNHEALTHY.")
            print("System is UNHEALTHY. Check logs for remediation steps.")
            return

        logger.info(f"--- 🧿 The Eye is watching: {identifier} ---")
        
        # 2. Data Ingestion Layer (Initial + Recursive)
        await self.start_discovery_thread(identifier, "initial_target")
        
        logger.info("Waiting for recursive discovery to settle...")
        await asyncio.sleep(20) # Placeholder for task queue
        logger.info("Discovery phase complete. Starting analysis.")

        # 3. Core Analytical Phase
        self.final_analysis.metrics = self.graph_db.get_graph_metrics()
        await self.perform_graph_analytics()
        await self.perform_narrative_analysis()
        
        # 4. Predictive Phase
        await self.perform_predictive_analysis()
        
        # 5. AI Synthesis Phase
        await self.perform_ai_analysis()
        
        # 6. Reporting Phase
        report_paths = await self.generate_report()
        
        # 7. Metacognition (Self-Learning) Phase
        await self.perform_metacognitive_review()

        # 8. Archiving Phase
        await self.save_run_to_db()

        # 9. Final Output
        logger.info(f"--- 🧿 The Eye discovery complete for {identifier} ---")
        print(f"\nDiscovery complete. Report generated at: {report_paths.get('pdf')}")
        print(f"JSON export at: {report_paths.get('json')}")
        print(f"Exposure Score: {self.final_analysis.exposure_score:.0f}/100")
        print(f"Entities Found: {self.final_analysis.metrics.get('node_count', 0)}")
        print(f"Low-Confidence Items Logged: {len(self.low_confidence_log)}")


# --- NEW: Refinement 1 (Initialization Safety) ---
# This allows the file to be run directly as a script for testing.
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run 🧿 The Eye OSINT Platform.")
    parser.add_argument("identifier", type=str, help="The target to investigate (e.g., 'acme.com')")
    args = parser.parse_args()
    
    try:
        asyncio.run(TheEye().run(args.identifier))
    except KeyboardInterrupt:
        logger.info("Run cancelled by user.")