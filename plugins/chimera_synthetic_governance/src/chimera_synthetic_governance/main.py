from chimera_intel.core.plugin_interface import (
    Plugin,
    register_plugin,
    get_plugin_manager,
)
from chimera_intel.core.synthetic_media_governance import (
    apply_visible_watermark,
    detect_synthetic_artifacts,
    log_abuse_report,
    get_abuse_report,
)
# 'bytes' is a built-in and not imported from 'typing'
from typing import Dict, Any 

class SyntheticGovernancePlugin(Plugin):
    """
    Plugin for ethical governance of synthetic media.
    Provides tools for watermarking, detection, and abuse logging.
    """
    name = "synthetic_governance"

    def get_commands(self) -> Dict[str, Any]:
        """
        Expose governance functions directly as plugin commands.
        
        Usage:
        pm.exec('synthetic_governance.apply_watermark', image_bytes, label="Custom")
        pm.exec('synthetic_governance.detect_artifacts', file_bytes)
        pm.exec('synthetic_governance.log_abuse_report', 'asset_id_123', 'reporter', 'Reason')
        pm.exec('synthetic_governance.get_abuse_report', 'abuse_id_456')
        """
        return {
            "apply_watermark": apply_visible_watermark,
            "detect_artifacts": detect_synthetic_artifacts,
            "log_abuse_report": log_abuse_report,
            "get_abuse_report": get_abuse_report,
        }

# Register the plugin with the manager
@register_plugin
def initialize():
    plugin_manager = get_plugin_manager()
    plugin_manager.register_plugin(SyntheticGovernancePlugin())