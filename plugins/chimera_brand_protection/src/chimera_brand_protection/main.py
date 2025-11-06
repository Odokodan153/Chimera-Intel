# plugins/chimera_brand_protection/src/chimera_brand_protection/main.py

import asyncio
import typer
from fastapi import APIRouter, Body, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

# Use the same base class as the example
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.database import Database # Assuming global DB access

# Import the core logic and models from the main 'src' directory
from chimera_intel.core.brand_protection_pipeline import (
    BrandProtectionPipeline, 
    TriageTask
)

# --- API Data Models ---

class TriageSubmission(BaseModel):
    is_positive: bool
    notes: str

# --- Plugin Definition ---

class BrandProtectionPlugin(ChimeraPlugin):
    """
    This class is the "glue" that registers the BrandProtectionPipeline
    with the main Chimera Intel application.
    """
    
    def __init__(self):
        self.pipeline: Optional[BrandProtectionPipeline] = None
        self.background_tasks: List[asyncio.Task] = []
        super().__init__()

    @property
    def name(self) -> str:
        """
        This defines the top-level name for configuration.
        """
        return "brand-protection"

    @property
    def app(self) -> typer.Typer:
        """
        This plugin is a background service and does not offer CLI commands.
        It returns an empty Typer app to satisfy the interface.
        """
        return typer.Typer(name=self.name, help="Brand protection monitoring service (no CLI commands).")

    async def initialize(self, config: Dict[str, Any]):
        """
        Initializes the pipeline and starts its background worker tasks.
        This is called by the plugin manager on startup.
        """
        try:
            db_session = Database().get_session() # Get a DB session
            self.pipeline = BrandProtectionPipeline(db_session=db_session)
            
            # Use the 'name' property to find its config block
            pipeline_config = config.get(self.name, {})
            brand_keywords = pipeline_config.get("brand_keywords", [])
            brand_images = pipeline_config.get("brand_image_paths", [])
            
            # Create and store background tasks
            self.background_tasks.append(
                asyncio.create_task(self.pipeline.run_monitoring(brand_keywords, brand_images))
            )
            self.background_tasks.append(
                asyncio.create_task(self.pipeline.run_ingestion_pipeline())
            )
            self.background_tasks.append(
                asyncio.create_task(self.pipeline.run_triage_intake())
            )
            self.background_tasks.append(
                asyncio.create_task(self.pipeline.run_threat_scoring())
            )
            print(f"Successfully initialized {self.name} with {len(self.background_tasks)} workers.")
        except Exception as e:
            print(f"ERROR initializing {self.name}: {e}")

    async def shutdown(self):
        """
        Gracefully cancels all running background tasks.
        This is called by the plugin manager on shutdown.
        """
        for task in self.background_tasks:
            task.cancel()
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        print(f"Shut down {self.name}.")

    def get_api_routes(self) -> APIRouter:
        """
        Exposes API endpoints for the analyst triage workflow.
        This is called by the plugin manager to attach routes to the main FastAPI app.
        """
        router = APIRouter(prefix=f"/{self.name}", tags=["Brand Protection"])

        @router.get("/triage/pending", response_model=List[TriageTask])
        async def get_pending_tasks():
            """
            Get all pending triage tasks for the analyst UI.
            """
            if not self.pipeline:
                raise HTTPException(status_code=503, detail="Pipeline not initialized.")
            return await self.pipeline.get_pending_triage_tasks()

        @router.post("/triage/submit/{task_id}", response_model=Dict[str, Any])
        async def submit_triage_result(task_id: str, submission: TriageSubmission):
            """
            Submit an analyst's validation for a task.
            """
            if not self.pipeline:
                raise HTTPException(status_code=503, detail="Pipeline not initialized.")
            try:
                return await self.pipeline.submit_triage_result(
                    task_id, submission.is_positive, submission.notes
                )
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))
        
        return router
