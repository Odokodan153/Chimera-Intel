# plugins/chimera_synthetic_media/src/chimera_synthetic_media/main.py

import click
from fastapi import APIRouter, Depends, HTTPException, Body
from typing import List, Optional

from chimera_intel.core.plugin_interface import PluginInterface, ChimeraContext
from chimera_intel.core.synthetic_media_generator import (
    SyntheticMediaGenerator,
    AllowedUseCase,
    GenerationType,
    SyntheticMediaRequest,
    GeneratedAsset,
    ConsentArtifact,
    EnvSecretProvider, # Import the concrete provider
    SecretProvider
)
from chimera_intel.core.ethical_guardrails import DisallowedUseCaseError
from pydantic import BaseModel

# --- Dependency Injection for FastAPI ---

_generator: SyntheticMediaGenerator = None
_secret_provider: SecretProvider = None # Store the provider

def get_generator() -> SyntheticMediaGenerator:
    """FastAPI dependency to get the initialized generator instance."""
    if _generator is None:
        raise RuntimeError("SyntheticMediaGenerator plugin not initialized.")
    return _generator

# --- API Request Models ---

class ConsentRegistrationRequest(BaseModel):
    subject_name: str
    document_vault_id: str
    identity_verified: bool = False
    voice_consent_phrase: Optional[str] = None
    source_audio_vault_id: Optional[str] = None

class GenerationRequest(BaseModel):
    operator_id: str
    use_case: AllowedUseCase
    generation_type: GenerationType
    consent_id: str
    
    # Generation-specific params
    generation_prompt: Optional[str] = None
    target_text: Optional[str] = None
    source_media_vault_id: Optional[str] = None
    driving_media_vault_id: Optional[str] = None


# --- Plugin Class ---

class SyntheticMediaPlugin(PluginInterface):
    """
    Plugin to integrate the SyntheticMediaGenerator service.
    """
    
    def name(self) -> str:
        return "Synthetic Media Generator"

    def initialize(self, context: ChimeraContext) -> None:
        """
        Initializes the generator service and registers it with the plugin.
        """
        global _generator, _secret_provider
        
        plugin_config = context.config.get_plugin_config("synthetic_media", {
            # Key itself is GONE. Only the NAME remains.
            "PROVENANCE_SIGNING_KEY_NAME": "CHIMERA_PROVENANCE_KEY", 
            "MODEL_CACHE_DIR": context.config.get_data_path("models/synthetic_media"),
            # --- Add new config key ---
            "FOMM_CHECKPOINT_PATH": None # Must be set in config.yaml
        })

        if not plugin_config.get("FOMM_CHECKPOINT_PATH"):
            context.logger.log_warning(
                "Synthetic Media plugin: 'FOMM_CHECKPOINT_PATH' is not set in config. Face reenactment will be disabled.",
                {"plugin": self.name()}
            )

        # --- SECURITY HARDENING ---
        # Instantiate the secret provider.
        _secret_provider = EnvSecretProvider()
        # --- END SECURITY HARDENING ---

        try:
            self.generator = SyntheticMediaGenerator(
                vault=context.services.forensic_vault,
                guardrails=context.services.ethical_guardrails,
                logger=context.services.audit_logger,
                config=plugin_config, # Pass the full config
                secret_provider=_secret_provider # Pass the provider
            )
        except (ValueError, KeyError) as e:
            # This will catch errors from the provider (e.g., env var not set)
            context.logger.log_critical(
                f"Synthetic Media plugin failed to load: {e}",
                {"plugin": self.name()}
            )
            # Prevent plugin from loading if secrets are missing
            raise
        
        _generator = self.generator
        context.logger.log_info("Synthetic Media Generator plugin initialized (production-ready).", {"plugin": self.name()})

    def get_api_endpoints(self) -> List[APIRouter]:
        """
        Provides FastAPI endpoints for the generation workflow.
        """
        router = APIRouter(prefix="/synthetic-media", tags=["Synthetic Media"])

        @router.post("/consent", response_model=ConsentArtifact)
        def register_consent(
            request: ConsentRegistrationRequest,
            generator: SyntheticMediaGenerator = Depends(get_generator)
        ):
            """Registers a new consent artifact, including optional voice verification parameters."""
            try:
                # Use **request.dict() to unpack Pydantic model
                return generator.register_consent(**request.dict())
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @router.post("/request", response_model=SyntheticMediaRequest)
        def request_generation(
            request: GenerationRequest,
            generator: SyntheticMediaGenerator = Depends(get_generator)
        ):
            """Submits a new synthetic media generation request for approval."""
            try:
                # Use **request.dict() to unpack Pydantic model
                return generator.request_synthetic_media(**request.dict())
            except (DisallowedUseCaseError, PermissionError) as e:
                raise HTTPException(status_code=403, detail=str(e))
            except (ValueError, NotImplementedError) as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @router.post("/request/{request_id}/approve", response_model=SyntheticMediaRequest)
        def approve_generation_request(
            request_id: str,
            approver_id: str = Body(..., embed=True),
            generator: SyntheticMediaGenerator = Depends(get_generator)
        ):
            """Approves a pending generation request. This triggers secondary verification (if applicable)."""
            try:
                return generator.approve_request(approver_id=approver_id, request_id=request_id)
            except PermissionError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))

        @router.post("/request/{request_id}/generate", response_model=GeneratedAsset)
        def execute_generation(
            request_id: str,
            generator: SyntheticMediaGenerator = Depends(get_generator)
        ):
            """Triggers the execution of an approved generation request."""
            try:
                return generator.execute_generation(request_id=request_id)
            except PermissionError as e:
                raise HTTPException(status_code=403, detail=str(e))
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Generation failed: {e}")

        return [router]

    def get_cli_commands(self) -> List[click.Command]:
        """
        Provides Click CLI commands for managing the generation workflow.
        """
        
        @click.group(name="synthetic-media", help="Consent-gated synthetic media generation.")
        def sm_cli():
            pass

        @sm_cli.command(name="register-consent", help="Register a new consent artifact.")
        @click.option("--subject", required=True)
        @click.option("--doc-id", "document_vault_id", required=True)
        @click.option("--verified", is_flag=True, help="Set if identity was verified.")
        @click.option("--voice-phrase", "voice_consent_phrase", help="Required phrase for voice consent.")
        @click.option("--voice-audio-id", "source_audio_vault_id", help="Vault ID of audio for voice consent.")
        def register_consent(subject, document_vault_id, verified, voice_consent_phrase, source_audio_vault_id):
            if _generator is None:
                click.echo("Error: Plugin not initialized.", err=True)
                return
            try:
                consent = _generator.register_consent(
                    subject_name=subject,
                    document_vault_id=document_vault_id,
                    identity_verified=verified,
                    voice_consent_phrase=voice_consent_phrase,
                    source_audio_vault_id=source_audio_vault_id
                )
                click.echo(f"Consent registered. Consent ID: {consent.consent_id}")
            except Exception as e:
                click.echo(f"Error: {e}", err=True)

        @sm_cli.command(name="request", help="Request a new synthetic media generation.")
        @click.option("--operator-id", required=True)
        @click.option("--use-case", required=True, type=click.Choice([e.value for e in AllowedUseCase]))
        @click.option("--type", "gen_type", required=True, type=click.Choice([e.value for e in GenerationType]))
        @click.option("--consent-id", required=True)
        # Type-specific options
        @click.option("--prompt", help="Text prompt for [fully_synthetic_face]")
        @click.option("--text", "target_text", help="Target text for [voice_clone]")
        @click.option("--source-id", "source_media_vault_id", help="Source media ID for [face_reenactment]")
        @click.option("--driving-id", "driving_media_vault_id", help="Driving media ID for [face_reenactment]")
        def request(operator_id, use_case, gen_type, consent_id, prompt, target_text, source_media_vault_id, driving_media_vault_id):
            if _generator is None:
                click.echo("Error: Plugin not initialized.", err=True)
                return
            try:
                req = _generator.request_synthetic_media(
                    operator_id=operator_id,
                    use_case=AllowedUseCase(use_case),
                    generation_type=GenerationType(gen_type),
                    consent_id=consent_id,
                    generation_prompt=prompt,
                    target_text=target_text,
                    source_media_vault_id=source_media_vault_id,
                    driving_media_vault_id=driving_media_vault_id
                )
                click.echo(f"Request submitted. Status: {req.status.value}, ID: {req.request_id}")
            except Exception as e:
                click.echo(f"Error: {e}", err=True)

        @sm_cli.command(name="approve", help="Approve a pending request (triggers verification).")
        @click.option("--request-id", required=True)
        @click.option("--approver-id", required=True)
        def approve(request_id, approver_id):
            if _generator is None:
                click.echo("Error: Plugin not initialized.", err=True)
                return
            try:
                req = _generator.approve_request(approver_id, request_id)
                click.echo(f"Request {req.request_id} approved by {req.approver_id}.")
            except Exception as e:
                click.echo(f"Error: {e}", err=True)
        
        @sm_cli.command(name="generate", help="Execute an approved generation request.")
        @click.option("--request-id", required=True)
        def generate(request_id):
            if _generator is None:
                click.echo("Error: Plugin not initialized.", err=True)
                return
            try:
                asset = _generator.execute_generation(request_id)
                click.echo(f"Generation complete. Asset ID: {asset.asset_id}, Vault Path: {asset.vault_file_path}")
            except Exception as e:
                click.echo(f"Error: {e}", err=True)

        return [sm_cli]

# Create the plugin instance for the core to load
plugin = SyntheticMediaPlugin()