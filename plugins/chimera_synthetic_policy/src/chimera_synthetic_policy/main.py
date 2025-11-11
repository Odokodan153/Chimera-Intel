from chimera_intel.core.plugin_interface import (
    Plugin,
    register_plugin,
    get_plugin_manager,
)
from chimera_intel.core.synthetic_media_policy import (
    check_generation_policy,
    get_retention_policy_text,
)
# The GenerationRequest and PolicyCheckResult models are imported
# by the *caller* from the core module, not exposed by the plugin.
from typing import Dict, Any, Callable

class SyntheticPolicyPlugin(Plugin):
    """
    Plugin for pre-generation policy checks on synthetic media.
    Provides commands to check requests against policies and get
    retention information.
    """
    name = "synthetic_policy"

    def get_commands(self) -> Dict[str, Callable[..., Any]]:
        """
        Expose policy functions as plugin commands.
        
        Usage:
        
        # The caller must import the model from the core library
        from chimera_intel.core.synthetic_media_policy import GenerationRequest
        
        request = GenerationRequest(
            subject_name="stock_face_001",
            subject_category="stock_synthetic_face",
            use_case="internal_marketing",
            requesting_operator="op_test_user"
        )
        
        # Execute the check
        policy_result = pm.exec('synthetic_policy.check_request', request=request)
        
        if policy_result.is_allowed:
            print("Generation is allowed.")
        
        # Get retention policy text
        print(pm.exec('synthetic_policy.get_retention_policy'))
        """
        return {
            "check_request": check_generation_policy,
            "get_retention_policy": get_retention_policy_text,
        }

# Register the plugin with the manager
@register_plugin
def initialize():
    plugin_manager = get_plugin_manager()
    plugin_manager.register_plugin(SyntheticPolicyPlugin())