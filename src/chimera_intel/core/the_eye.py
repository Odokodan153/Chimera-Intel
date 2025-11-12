"""
🧿 THE EYE — OSINT Corporate Intelligence Platform (Phases 3 & 4)
Codename: "The Eye"
Role: Central AI intelligence, orchestrator, and data analyzer.
"""

import asyncio
import uuid
import logging
import redis  # For real cache health check
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
from chimera_intel.core.entity_resolver import EntityResolver
from chimera_intel.core.counter_intelligence import CounterIntelligence
from chimera_intel.core.honeypot_detector import HoneypotDetector
from chimera_intel.core.credibility_assessor import CredibilityAssessor
from chimera_intel.core.ethical_guardrails import EthicalGuardrails
from chimera_intel.core.source_trust_model import SourceTrustModel
from chimera_intel.core.strategist import Strategist
from chimera_intel.core.source_triage import SourceTriage
from chimera_intel.core.graph_analyzer import GraphAnalyzer
from chimera_intel.core.correlation_engine import CorrelationEngine
from chimera_intel.core.temporal_analyzer import TemporalAnalyzer
from chimera_intel.core.topic_clusterer import TopicClusterer
from chimera_intel.core.narrative_analyzer import NarrativeAnalyzer
from chimera_intel.core.disinformation_analyzer import DisinformationAnalyzer
from chimera_intel.core.cultural_sentiment import CulturalSentiment
from chimera_intel.core.risk_assessment import RiskAssessment
from chimera_intel.core.opsec_analyzer import OpsecAnalyzer
from chimera_intel.core.wargaming_engine import WargamingEngine
from chimera_intel.core.attack_path_simulator import AttackPathSimulator
from chimera_intel.core.alternative_hypothesis_generator import AlternativeHypothesisGenerator
from chimera_intel.core.strategic_forecaster import StrategicForecaster
from chimera_intel.core.metacognition import Metacognition
from chimera_intel.core.grapher_3d import Grapher3D

# --- Phase 3 & 4 Imports ---
from chimera_intel.core.enterprise_audit import EnterpriseAuditor
from chimera_intel.core.alert_manager import AlertManager

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

# --- Data Schemas ---

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
    banner_displayed: bool = False
    api_connections_alive: bool = False
    api_quota_status: str = "unknown"
    osint_modules_loaded: int = 0
    database_connection: str = "disconnected"
    cache_connection: str = "disconnected"
    config_schema_version: str = "mismatch"
    threads_running: int = 0
    pii_detected: List[str] = Field(default_factory=list)
    legal_compliance: str = "not_passed"
    errors_in_last_run: List[str] = Field(default_factory=list)
    healthy: bool = False
    remediation_steps: List[str] = Field(default_factory=list)

class FullAnalysisReport(BaseModel):
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
    Now multi-tenant and integrated with auditing and alerting.
    """

    def __init__(self, tenant_id: str):
        """
        --- Component 1: Initialization Layer ---
        Requires a tenant_id for data isolation.
        """
        logger.info(f"Initializing 🧿 The Eye for tenant: {tenant_id}")
        self.tenant_id = tenant_id
        
        # --- Load Core Components ---
        self.config_loader = ConfigLoader()
        self.config = self.config_loader.load_config()
        self.plugin_manager = PluginManager(plugin_dir="plugins")
        self.graph_db = GraphDB() # Must be multi-tenant
        self.gemini_client = GeminiClient()
        self.reporter = Reporter() # Will be updated
        self.guardrails = EthicalGuardrails()

        self.osint_plugins: List[ChimeraPlugin] = self.plugin_manager.load_plugins()

        # --- Data Stores & State ---
        self.entities: Dict[str, DiscoveryRecord] = {}
        self.relations: List[Dict[str, Any]] = []
        self.discovered_identifiers: Set[str] = set()
        self.raw_text_corpus: List[str] = []
        self.low_confidence_log: List[Dict[str, Any]] = []
        self.health_report = SystemHealthReport()
        self.final_analysis = FullAnalysisReport()
        self.initial_identifier: Optional[str] = None
        self.discovery_semaphore = asyncio.Semaphore(10) # Concurrency control

        # --- Real Cache Client ---
        try:
            self.cache_client = redis.Redis(
                host=self.config['redis']['host'],
                port=self.config['redis']['port'],
                db=0,
                decode_responses=True
            )
            self.cache_client.ping()
            logger.info("Redis cache client initialized and connected.")
        except Exception as e:
            logger.error(f"Failed to initialize Redis cache client: {e}")
            self.cache_client = None

        # --- Instantiate All Logical Engines ---
        self.entity_resolver = EntityResolver(self.entities)
        self.credibility_assessor = CredibilityAssessor()
        self.honeypot_detector = HoneypotDetector()
        self.counter_intelligence = CounterIntelligence()
        self.source_trust_model = SourceTrustModel()
        self.strategist = Strategist()
        self.source_triage = SourceTriage(self.source_trust_model)
        self.graph_analyzer = GraphAnalyzer(self.graph_db, self.tenant_id)
        self.correlation_engine = CorrelationEngine(self.graph_db, self.tenant_id)
        self.temporal_analyzer = TemporalAnalyzer()
        self.topic_clusterer = TopicClusterer()
        self.narrative_analyzer = NarrativeAnalyzer()
        self.disinformation_analyzer = DisinformationAnalyzer()
        self.cultural_sentiment = CulturalSentiment()
        self.risk_assessment = RiskAssessment()
        self.opsec_analyzer = OpsecAnalyzer()
        self.wargaming_engine = WargamingEngine()
        self.attack_path_simulator = AttackPathSimulator(self.graph_db, self.tenant_id)
        self.alternative_hypothesis_gen = AlternativeHypothesisGenerator()
        self.forecaster = StrategicForecaster()
        self.metacognition = Metacognition()
        self.grapher_3d = Grapher3D()

        # --- Phase 4 Modules ---
        self.audit = EnterpriseAuditor(tenant_id=self.tenant_id)
        self.alert_manager = AlertManager() # Will be updated


    # --- 1. System Health Check ---

    def check_cache_health(self) -> str:
        """
        Real health check for Redis.
        """
        if not self.cache_client:
            return "disconnected"
        try:
            self.cache_client.ping()
            return "ok"
        except Exception as e:
            logger.warning(f"Cache health check (ping) failed: {e}")
            return "disconnected"

    def check_system_health(self) -> SystemHealthReport:
        """AI agent validation checklist."""
        report = SystemHealthReport()
        report.banner_displayed = True
        
        try:
            if self.gemini_client.is_configured():
                report.api_connections_alive = True
                report.api_quota_status = "ok" # Placeholder
            else:
                report.remediation_steps.append("Check Gemini/OpenAI API key.")
        except Exception as e:
            report.errors_in_last_run.append(f"API check error: {e}")

        report.osint_modules_loaded = len(self.osint_plugins)
        if report.osint_modules_loaded == 0:
            report.remediation_steps.append("No OSINT plugins found.")
            
        if self.graph_db.is_connected():
            report.database_connection = "ok"
        else:
            report.database_connection = "disconnected"
            report.remediation_steps.append("GraphDB is not connected.")
            
        report.cache_connection = self.check_cache_health()
        if report.cache_connection != "ok":
            report.remediation_steps.append("Cache (Redis) is not connected.")
            
        config_version = self.config.get('config_version', 'mismatch') # Check config
        if config_version == "1.1": # Set expected version
            report.config_schema_version = "ok"
        else:
            report.remediation_steps.append(f"Config schema mismatch. Expected 1.1, found {config_version}.")
        
        if self.guardrails.is_enabled():
            report.legal_compliance = "passed"
        else:
            report.remediation_steps.append("Ethical Guardrails are not enabled.")

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
            self.audit.log_system_health_fail(report.remediation_steps) # Audit
        else:
            logger.info("System health check: PASSED")
        return report

    # --- 2. Data Ingestion & Processing Pipeline ---
    
    async def start_discovery_thread(self, identifier: str, entity_type: Optional[str] = None):
        """
        Runs a *strategic* set of OSINT plugins against a single identifier.
        """
        logger.info(f"Starting discovery thread for: {identifier} (Type: {entity_type})")
        
        plan = self.strategist.get_plan(identifier, entity_type, list(self.entities.values()))
        plugins_to_run = self.source_triage.get_prioritized_plugins(plan, self.osint_plugins)
        logger.debug(f"Strategist selected {len(plugins_to_run)} plugins for {identifier}.")
        
        async def _discover_task(plugin: ChimeraPlugin, identifier: str):
            """Helper to wrap discovery with semaphore."""
            async with self.discovery_semaphore:
                logger.debug(f"[{identifier}] Running plugin: {plugin.name}")
                return await plugin.discover(identifier)

        tasks = [_discover_task(plugin, identifier) for plugin in plugins_to_run]
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
        if not self.guardrails.validate_record(record):
            logger.warning(f"Skipping record {record.identifier} (Source: {record.source}) due to compliance failure.")
            return

        record = self.counter_intelligence.analyze(record)
        record.confidence = self.credibility_assessor.assess(record)
        if self.honeypot_detector.is_honeypot(record):
            record.tags.add("honeypot")
            record.confidence = 0.1
            logger.warning(f"Honeypot detected: {record.identifier}")

        if record.confidence < 0.2:
            self.low_confidence_log.append({
                "identifier": record.identifier, "type": record.type,
                "source": record.source, "confidence": record.confidence,
                "timestamp": record.timestamp.isoformat()
            })
            return

        existing_entity_id = self.entity_resolver.resolve(record)
        if existing_entity_id:
            self.entity_resolver.merge(existing_entity_id, record)
            updated_record = self.entities[existing_entity_id]
            self.graph_db.update_node_properties(
                node_id=existing_entity_id,
                properties={"confidence": updated_record.confidence, "metadata": updated_record.metadata},
                tenant_id=self.tenant_id # Multi-tenant
            )
            return

        logger.info(f"Adding new entity to graph: {record.type} -> {record.identifier}")
        self.entities[record.id] = record
        self.graph_db.add_node(
            node_id=record.id,
            label=record.type,
            properties=record.model_dump(),
            tenant_id=self.tenant_id # Multi-tenant
        )
        
        for link in record.links:
            if link.target_id in self.entities:
                self.graph_db.add_edge(
                    source_id=record.id,
                    target_id=link.target_id,
                    label=link.relation.upper(),
                    properties={"evidence": link.evidence, "timestamp": record.timestamp},
                    tenant_id=self.tenant_id # Multi-tenant
                )
                self.relations.append({ "source": record.id, "target": link.target_id, "relation": link.relation })

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
        if max_value == 0: return 0.0
        return max(0.0, min(1.0, value / max_value))

    def calculate_exposure_score(self) -> float:
        """
        Runs a detailed, normalized formula to calculate exposure.
        """
        logger.info("Calculating normalized exposure score...")
        try:
            entity_list = list(self.entities.values())
            opsec_findings = self.opsec_analyzer.analyze(entity_list)
            risk_data = self.risk_assessment.assess(entity_list)
            
            pii_count = risk_data.get('pii_count', 0)
            leak_count = risk_data.get('credential_leaks', 0)
            public_asset_count = opsec_findings.get('public_buckets', 0) + opsec_findings.get('public_repos', 0)
            connectivity = self.final_analysis.metrics.get('edge_count', 0) / (self.final_analysis.metrics.get('node_count', 1) or 1)

            # Normalize factors
            normalized_pii_exposure = self._normalize(pii_count, 50)
            credential_leak_factor = self._normalize(leak_count, 10)
            opsec_public_asset_factor = self._normalize(public_asset_count, 20)
            graph_connectivity_factor = self._normalize(connectivity, 5)
            
            # Apply weighted formula
            score = (
                (0.3 * normalized_pii_exposure) +
                (0.3 * credential_leak_factor) +
                (0.2 * opsec_public_asset_factor) +
                (0.2 * graph_connectivity_factor)
            ) * 100
            
            return max(0.0, min(100.0, score)) # Cap to [0, 100]
        except Exception as e:
            logger.error(f"Failed to calculate exposure score: {e}")
            return 0.0

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
        except Exception as e: logger.error(f"Graph analytics failed: {e}")

    async def perform_narrative_analysis(self):
        """Analyzes the public narrative and discourse."""
        logger.info("Performing narrative analysis...")
        if not self.raw_text_corpus: return
        try:
            topics = self.topic_clusterer.cluster(self.raw_text_corpus)
            self.final_analysis.narrative_analysis = {
                "topics": topics,
                "narratives": self.narrative_analyzer.analyze(topics),
                "disinformation_flags": self.disinformation_analyzer.detect(topics),
                "overall_sentiment": self.cultural_sentiment.analyze(self.raw_text_corpus)
            }
        except Exception as e: logger.error(f"Narrative analysis failed: {e}")

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
        except Exception as e: logger.error(f"Predictive analysis failed: {e}")

    async def perform_ai_analysis_and_alerting(self):
        """
        Final AI synthesis and automated alerting (Phase 4).
        """
        logger.info("Performing final AI analysis and checking for alert triggers...")
        
        self.final_analysis.pii_found = [e.identifier for e in self.entities.values() if e.type in ('email', 'phone', 'person', 'credential')]
        self.final_analysis.exposure_score = self.calculate_exposure_score()

        # --- AI Summary Prompt ---
        prompt = f"""
        Analyze this pre-computed OSINT report.
        Target: {self.initial_identifier}
        Exposure Score: {self.final_analysis.exposure_score:.0f}/100
        Metrics: {self.final_analysis.metrics}
        Graph Analysis: {self.final_analysis.graph_analytics}
        Narrative Analysis: {self.final_analysis.narrative_analysis}
        Predictive Analysis: {self.final_analysis.predictive_analysis}
        
        Generate:
        1. Executive Summary
        2. Key Findings & Anomalies
        3. Prioritized Risks & Attack Paths
        4. Intelligence Gaps & Next Steps
        """
        
        try:
            self.final_analysis.ai_summary = await self.gemini_client.generate_text(prompt)
        except Exception as e:
            logger.error(f"AI summary generation failed: {e}")
            self.final_analysis.ai_summary = "AI analysis failed to run."

        # --- Automated Alerting (Phase 4) ---
        risk_data = self.risk_assessment.assess(list(self.entities.values()))
        credential_leaks = risk_data.get('credential_leaks', 0)
        
        if self.final_analysis.exposure_score > 90:
            details = {"target": self.initial_identifier, "score": self.final_analysis.exposure_score}
            self.alert_manager.trigger_alert("CRITICAL_EXPOSURE", details, tenant_id=self.tenant_id)
            self.audit.log_alert_triggered("CRITICAL_EXPOSURE", details)

        if credential_leaks > 0:
            details = {"target": self.initial_identifier, "leaks_found": credential_leaks}
            self.alert_manager.trigger_alert("CREDENTIAL_LEAK", details, tenant_id=self.tenant_id)
            self.audit.log_alert_triggered("CREDENTIAL_LEAK", details)
            
        if self.final_analysis.narrative_analysis.get("disinformation_flags"):
            details = {"target": self.initial_identifier, "flags": self.final_analysis.narrative_analysis["disinformation_flags"]}
            self.alert_manager.trigger_alert("DISINFORMATION_CAMPAIGN", details, tenant_id=self.tenant_id)
            self.audit.log_alert_triggered("DISINFORMATION_CAMPAIGN", details)

    # --- 4. Reporting & Metacognition ---

    async def generate_report(self) -> Dict[str, str]:
        """Generates PDF and JSON reports."""
        logger.info("Generating Deep Intelligence Report...")
        
        graph_2d_path, graph_3d_path = None, None
        try:
            graph_2d_path = self.graph_db.export_graph_visualization(
                format="png", filename="the_eye_2d_graph", tenant_id=self.tenant_id
            )
        except Exception as e: logger.error(f"Failed to generate 2D graph: {e}")
        try:
            graph_3d_path = self.grapher_3d.generate_3d_graph(
                nodes=self.entities.values(), edges=self.relations, filename="the_eye_3d_graph"
            )
        except Exception as e: logger.error(f"Failed to generate 3D graph: {e}")
            
        report_data = {
            "title": f"The Eye: Deep Intelligence Report for {self.initial_identifier}",
            "tenant_id": self.tenant_id,
            "timestamp": datetime.utcnow().isoformat(),
            "health_report": self.health_report.model_dump(),
            "analysis": self.final_analysis.model_dump(),
            "low_confidence_log": self.low_confidence_log,
            "visualizations": {"graph_2d_path": graph_2d_path, "graph_3d_path": graph_3d_path}
        }
        
        pdf_path, json_path = "", ""
        try:
            pdf_path = self.reporter.generate_pdf(report_data, "the_eye_report")
            logger.info(f"Report generated: {pdf_path}")
        except Exception as e: logger.error(f"Failed to generate PDF report: {e}")
        try:
            json_path = self.reporter.export_json(report_data, "the_eye_report")
            logger.info(f"JSON export generated: {json_path}")
        except Exception as e: logger.error(f"Failed to export JSON report: {e}")

        report_paths = {"pdf": pdf_path, "json": json_path}
        self.audit.log_report_generation(self.initial_identifier, report_paths) # Audit
        return report_paths

    async def perform_metacognitive_review(self):
        """Learns from its own performance to improve future runs."""
        logger.info("Performing metacognitive review...")
        try:
            run_stats = {
                "total_entities": len(self.entities),
                "total_relations": len(self.relations),
                "plugins_run_count": len(self.plugin_manager.get_plugins_run_stats()),
                "low_confidence_items": len(self.low_confidence_log)
            }
            self.final_analysis.run_statistics = run_stats
            lessons_learned = self.metacognition.analyze_run(run_stats, list(self.entities.values()))
            self.source_trust_model.update_from_lessons(lessons_learned)
            logger.info("Source trust model updated.")
        except Exception as e: logger.error(f"Metacognitive review failed: {e}")

    # --- 5. Run Archiving ---
    
    async def save_run_to_db(self):
        """Saves a summary of this investigation run to the graph database."""
        logger.info("Archiving investigation run to database...")
        run_id = f"run-{self.tenant_id}-{uuid.uuid4()}"
        run_properties = {
            "run_id": run_id,
            "tenant_id": self.tenant_id,
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
            self.graph_db.add_node(
                node_id=run_id,
                label="InvestigationRun",
                properties=run_properties,
                tenant_id=self.tenant_id # Multi-tenant
            )
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
        self.audit.log_investigation_start(identifier) # Audit
        if not self.check_system_health().healthy:
            logger.error("The Eye cannot run. System is UNHEALTHY.")
            return

        logger.info(f"--- 🧿 The Eye is watching: {identifier} (Tenant: {self.tenant_id}) ---")
        
        # 2. Data Ingestion Layer
        await self.start_discovery_thread(identifier, "initial_target")
        
        logger.info("Waiting for recursive discovery...")
        await asyncio.sleep(20) # Placeholder for task queue
        logger.info("Discovery phase complete. Starting analysis.")

        # 3. Core Analytical Phase
        self.final_analysis.metrics = self.graph_db.get_graph_metrics(tenant_id=self.tenant_id)
        await self.perform_graph_analytics()
        await self.perform_narrative_analysis()
        
        # 4. Predictive Phase
        await self.perform_predictive_analysis()
        
        # 5. AI Synthesis & Alerting Phase
        await self.perform_ai_analysis_and_alerting()
        
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


# --- Main execution (for testing) ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run 🧿 The Eye OSINT Platform.")
    parser.add_argument("identifier", type=str, help="The target to investigate (e.g., 'acme.com')")
    parser.add_argument("--tenant", type=str, default="default_tenant", help="The tenant ID for this run.")
    args = parser.parse_args()
    
    try:
        asyncio.run(TheEye(tenant_id=args.tenant).run(args.identifier))
    except KeyboardInterrupt:
        logger.info("Run cancelled by user.")