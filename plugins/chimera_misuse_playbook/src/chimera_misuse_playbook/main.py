# plugins/chimera_misuse_playbook/src/chimera_misuse_playbook/main.py

from chimera_intel.core.plugin_interface import PluginInterface

# Import the real trigger functions from the core module
try:
    from chimera_intel.core.image_misuse_playbook import (
        trigger_image_misuse_playbook,
        trigger_takedown_from_approval
    )
except ImportError:
    # Handle case where core module isn't available during plugin discovery
    # or in a lightweight environment.
    def trigger_image_misuse_playbook(*args, **kwargs):
        raise RuntimeError("image_misuse_playbook core module not found.")
        
    def trigger_takedown_from_approval(*args, **kwargs):
        raise RuntimeError("image_misuse_playbook core module not found.")

class ChimeraMisusePlaybookPlugin(PluginInterface):
    """
    Plugin to expose the Image Misuse Takedown Playbook as actions.
    """
    
    def get_name(self) -> str:
        return "MisusePlaybook"

    def get_actions(self) -> dict:
        """
        Exposes the two entrypoints of the workflow.
        """
        return {
            "trigger_playbook": self.trigger_playbook,
            "approve_takedown": self.approve_takedown,
        }

    def trigger_playbook(self, context: dict) -> dict:
        """
        Starts the pre-approval evidence gathering workflow.
        
        Expected context:
        {
            "source_url": "http://example.com/stolen-image.png",
            "confidence": 0.85,
            "type": "misuse"
        }
        """
        source_url = context.get("source_url")
        confidence = context.get("confidence", 0.0)
        
        if not source_url:
            return {"status": "error", "message": "source_url not provided"}
            
        try:
            workflow_id = trigger_image_misuse_playbook(
                source_url=source_url,
                trigger_confidence=confidence,
                trigger_type=context.get("type", "misuse")
            )
            if workflow_id:
                return {
                    "status": "success",
                    "message": "Pre-approval workflow started.",
                    "workflow_id": workflow_id
                }
            else:
                return {"status": "error", "message": "Failed to start workflow, check Celery/Broker."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def approve_takedown(self, context: dict) -> dict:
        """
        Starts the post-approval takedown workflow.
        
        Expected context:
        {
            "review_task_id": "task_12345"
        }
        """
        task_id = context.get("review_task_id")
        
        if not task_id:
            return {"status": "error", "message": "review_task_id not provided"}
            
        try:
            workflow_id = trigger_takedown_from_approval(task_id)
            if workflow_id:
                return {
                    "status": "success",
                    "message": "Post-approval workflow started.",
                    "workflow_id": workflow_id
                }
            else:
                return {"status": "error", "message": "Failed to start workflow, check Celery/Broker."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

def register() -> PluginInterface:
    return ChimeraMisusePlaybookPlugin()