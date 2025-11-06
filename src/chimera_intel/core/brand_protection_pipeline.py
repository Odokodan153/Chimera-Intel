# src/chimera_intel/core/brand_protection_pipeline.py

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- Imports from existing core modules (schemas.py) ---
from chimera_intel.core.schemas import (
    IngestedImageRecord,
    ManipulationDetectionResult,
    BrandThreat,  
    TriageTask,   
)

# --- Imports from existing core modules (based on file list) ---
from chimera_intel.core.social_media_monitor import SocialMediaMonitor
from chimera_intel.core.dark_web_monitor import DarkWebMonitor
from chimera_intel.core.page_monitor import PageMonitor
from chimera_intel.core.imint import IMINT
from chimera_intel.core.image_forensics_pipeline import ImageForensicsPipeline
from chimera_intel.core.data_ingestion import DataIngestion
from chimera_intel.core.social_analyzer import SocialAnalyzer


class BrandProtectionPipeline:
    """
    Orchestrates the detection and monitoring pipeline by integrating
    monitoring, ingestion, ML detection, human triage, and threat scoring.
    """

    def __init__(self, db_session: Any):
        # 1. Continuous Monitoring (Monitors)
        self.social_monitor = SocialMediaMonitor()
        self.dark_web_monitor = DarkWebMonitor()
        self.web_monitor = PageMonitor()
        self.reverse_image_search = IMINT()

        # 2. Automated Ingestion (Services)
        self.data_ingestion = DataIngestion()
        self.detection_pipeline = ImageForensicsPipeline()

        # 3. Triage & Scoring
        self.social_analyzer = SocialAnalyzer()
        self.db = db_session  # Use a passed-in DB session (e.g., from Database())

        # Internal queues for orchestration
        self.alerts_queue = asyncio.Queue()
        self.triage_queue = asyncio.Queue()
        self.scoring_queue = asyncio.Queue()

    # --- 1. Continuous Monitoring ---

    async def run_monitoring(self, brand_keywords: List[str], brand_image_paths: List[str]):
        """
        Starts all monitoring tasks concurrently.
        """
        brand_image_features = await self.reverse_image_search.get_bulk_features(brand_image_paths)
        
        print("Starting continuous monitoring tasks...")
        tasks = [
            self.social_monitor.monitor_keywords(brand_keywords, self.alerts_queue),
            self.social_monitor.monitor_images(brand_image_features, self.alerts_queue),
            self.dark_web_monitor.monitor(brand_keywords, self.alerts_queue),
            self.web_monitor.monitor_domains(brand_keywords, self.alerts_queue)
        ]
        await asyncio.gather(*tasks)

    # --- 2. Automated Ingestion ---

    async def _process_one_alert(self, alert_data: Dict[str, Any]):
        """
        Processes a single alert from the monitoring queue.
        """
        try:
            print(f"Ingesting alert for: {alert_data.get('url')}")
            # Ingest media (frame extraction, metadata checks, etc.)
            # This now returns an IngestedImageRecord
            media_record: IngestedImageRecord = await self.data_ingestion.ingest_media(
                alert_data.get('url'),
                source_type=alert_data.get('source_type'),
                context_url=alert_data.get('context_url')
            )
            
            # Run ML detection
            # This now returns a ManipulationDetectionResult
            detection_result: ManipulationDetectionResult = await self.detection_pipeline.analyze(
                media_record.storage_key
            )
            
            # Triage logic now checks the sub-schema
            triage_flag = False
            if detection_result.deepfake_scan and detection_result.deepfake_scan.is_deepfake:
                if detection_result.deepfake_scan.confidence > 0.5: # Configurable threshold
                    triage_flag = True

            if triage_flag:
                print(f"Flagged for triage: {media_record.source_url}")
                await self.triage_queue.put((media_record, detection_result, alert_data))
            
        except Exception as e:
            print(f"Error processing alert {alert_data.get('url')}: {e}")

    async def run_ingestion_pipeline(self):
        """
        Continuously ingests flagged media from the alerts_queue.
        """
        while True:
            alert_data = await self.alerts_queue.get()
            await self._process_one_alert(alert_data)
            self.alerts_queue.task_done()

    # --- 3. False-Positive Triage ---

    async def run_triage_intake(self):
        """
        Continuously creates triage tasks from the triage_queue.
        """
        while True:
            media_record, detection_result, alert_data = await self.triage_queue.get()
            
            task = TriageTask(
                media_url=str(media_record.source_url),
                source=alert_data.get('source'),
                provenance_data=alert_data.get('provenance', {}),
                detection_result=detection_result
            )
            await self.db.save_triage_task(task.dict()) # Assumes DB method
            print(f"New triage task created: {task.task_id}")
            self.triage_queue.task_done()

    async def get_pending_triage_tasks(self) -> List[TriageTask]:
        """Fetches all tasks with 'pending' status for the analyst UI."""
        tasks_data = await self.db.get_tasks_by_status('pending')
        return [TriageTask(**data) for data in tasks_data]

    async def submit_triage_result(self, task_id: str, is_positive: bool, notes: str) -> Dict[str, Any]:
        """Updates a triage task with an analyst's validation."""
        task_data = await self.db.get_triage_task(task_id)
        if not task_data:
            raise ValueError(f"Task ID {task_id} not found.")
        
        task = TriageTask(**task_data)
        task.status = 'confirmed_positive' if is_positive else 'false_positive'
        task.analyst_notes = notes
        
        await self.db.update_triage_task(task_id, task.dict())
        
        if is_positive:
            # Send to threat scoring
            await self.scoring_queue.put(task)
            
        return {"message": "Triage complete", "task_id": task_id, "status": task.status}

    # --- 4. Threat Scoring ---

    async def _calculate_reach_score(self, source_url: str, provenance: Dict[str, Any]) -> float:
        """
        Combines detection score with reach/impact metrics.
        """
        source_type = provenance.get('source_type')
        
        if source_type == 'social':
            try:
                metrics = await self.social_analyzer.get_profile_metrics_by_post(source_url)
                followers = metrics.get('followers', 0)
                repost_rate = metrics.get('repost_rate', 0.0)
                
                follower_score = min(followers / 1_000_000.0, 1.0)
                repost_score = min(repost_rate / 0.05, 1.0)
                
                return (follower_score * 0.7) + (repost_score * 0.3)
                
            except Exception:
                return 0.1  # Low score if profile analysis fails
        
        elif source_type == 'dark_web':
            return 0.7
        elif source_type == 'web':
            return 0.3
            
        return 0.0

    async def _process_one_scoring_task(self, task: TriageTask):
        """Processes a single confirmed-positive task."""
        try:
            reach_score = await self._calculate_reach_score(task.media_url, task.provenance_data)
            
            # Get detection score from the corrected schema
            detection_score = 0.0
            if task.detection_result.deepfake_scan:
                detection_score = task.detection_result.deepfake_scan.confidence
            
            # Weighted final score: 60% reach, 40% detection confidence
            final_threat_score = (reach_score * 0.6) + (detection_score * 0.4)
            
            threat = BrandThreat(
                media_url=task.media_url,
                source=task.source,
                triage_status=task.status,
                detection_score=detection_score,
                reach_score=reach_score,
                final_threat_score=final_threat_score
            )
            
            await self.db.save_brand_threat(threat.dict())
            print(f"New threat scored: {threat.threat_id} (Score: {final_threat_score})")

        except Exception as e:
            print(f"Error scoring threat for task {task.task_id}: {e}")

    async def run_threat_scoring(self):
        """
        Continuously scores confirmed threats from the scoring_queue.
        """
        while True:
            task = await self.scoring_queue.get()
            await self._process_one_scoring_task(task)
            self.scoring_queue.task_done()