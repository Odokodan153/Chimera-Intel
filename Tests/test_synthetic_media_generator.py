# Tests/test_synthetic_media_generator.py

import pytest
from unittest.mock import MagicMock, patch, ANY
from pydantic import ValidationError
from PIL import Image
import io
import struct
import base64
from datetime import datetime, timezone
from abc import ABC

# Import the module to be tested
from src.chimera_intel.core.synthetic_media_generator import (
    SyntheticMediaGenerator,
    AllowedUseCase,
    GenerationType,
    RequestStatus,
    ConsentArtifact,
    DisallowedUseCaseError,
    ProvenanceTools,
    _NeuralWatermarker,
    _AudioWatermarker,
    SecretProvider, # Import new abstraction
    EnvSecretProvider,
    _decode_jwt_payload, # Import helper for testing
    TTS_MAX_LENGTH # Import for testing
)
# Import modules to be mocked
from src.chimera_intel.core.forensic_vault import ForensicVault
from src.chimera_intel.core.ethical_guardrails import EthicalGuardrails
from src.chimera_intel.core.audit_logger import AuditLogger

# --- Fixtures ---

@pytest.fixture
def mock_vault():
    """Mock fixture for ForensicVault."""
    vault = MagicMock(spec=ForensicVault)
    
    # Mock vault file reads
    mock_img_bytes = io.BytesIO()
    Image.new('RGB', (100, 100), color='green').save(mock_img_bytes, format='PNG')
    
    # Mock read_artifact_bytes to return different things based on path
    def read_bytes(path):
        if 'img' in path:
            return mock_img_bytes.getvalue()
        if 'vid' in path:
            return b"dummy_video_bytes_for_transform"
        return b"default_bytes"
        
    vault.read_artifact_bytes.side_effect = read_bytes
    
    # Mock local path access for audio
    vault.get_local_path.return_value = "/mock/vault/audio.wav"
    return vault

@pytest.fixture
def mock_guardrails():
    """Mock fixture for EthicalGuardrails."""
    mock = MagicMock(spec=EthicalGuardrails)
    mock.check_synthetic_media_policy.return_value = None
    return mock

@pytest.fixture
def mock_logger():
    """Mock fixture for AuditLogger."""
    return MagicMock(spec=AuditLogger)

@pytest.fixture
def mock_secret_provider():
    """Mock fixture for SecretProvider."""
    provider = MagicMock(spec=SecretProvider)
    # Use a key that meets the 16-char length requirement
    provider.get_secret.return_value = "test-secret-key-1234567890123456"
    return provider

@pytest.fixture
def mock_config():
    """Provides a valid config dictionary (now with secret NAME and FOMM path)."""
    return {
        "PROVENANCE_SIGNING_KEY_NAME": "TEST_SIGNING_KEY",
        "MODEL_CACHE_DIR": "/tmp/test-cache",
        "FOMM_CHECKPOINT_PATH": "/mock/fomm-checkpoint.pth" # Added
    }

# Patch the real ML/Hardware dependencies
@patch('src.chimera_intel.core.synthetic_media_generator.IsolatedGenerationRuntime', MagicMock())
@patch('src.chimera_intel.core.synthetic_media_generator.ProvenanceTools', MagicMock())
@pytest.fixture
def generator(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider):
    """Fixture for an initialized SyntheticMediaGenerator with new dependencies."""
    gen = SyntheticMediaGenerator(
        vault=mock_vault,
        guardrails=mock_guardrails,
        logger=mock_logger,
        config=mock_config,
        secret_provider=mock_secret_provider
    )
    
    # Mock the "real" helper classes
    gen.provenance = MagicMock()
    gen.runtime = MagicMock()
    
    # --- Mock runtime methods ---
    gen.runtime.generate_synthetic_face.return_value = Image.new('RGB', (100, 100), color='blue')
    # --- Reenactment now returns video bytes ---
    gen.runtime.perform_face_reenactment.return_value = b"mock_mp4_video_bytes"
    gen.runtime.clone_voice.return_value = b"RIFF....WAVEdata....mock_wav_bytes"
    gen.runtime.verify_voice_consent.return_value = True # Default to pass
    
    # --- Mock provenance methods ---
    gen.provenance.sign_metadata.return_value = "mock.jwt.token"
    mock_final_image = Image.new('RGB', (100, 100), color='yellow')
    mock_final_image.info = {"ChimeraIntelProvenance": "mock.jwt.token"}
    gen.provenance.embed_provenance.return_value = mock_final_image
    gen.provenance.embed_audio_provenance.return_value = b"watermarked_wav_bytes"
    
    # Add decode helper to mock
    with patch('src.chimera_intel.core.synthetic_media_generator._decode_jwt_payload') as mock_decode:
        mock_decode.return_value = {"decoded": "payload"}
        yield gen # Yield the generator for tests

@pytest.fixture
def face_consent(generator):
    """Registers a standard consent artifact."""
    return generator.register_consent(
        subject_name="Test Subject",
        document_vault_id="vault:doc-123",
        identity_verified=True
    )

@pytest.fixture
def voice_consent(generator):
    """Registers a consent artifact with voice verification."""
    return generator.register_consent(
        subject_name="Test Voice Subject",
        document_vault_id="vault:doc-456",
        identity_verified=True,
        voice_consent_phrase="I, Test Voice Subject, consent to this.",
        source_audio_vault_id="vault:audio-789"
    )

# --- Test Cases ---

def test_init_with_secret_provider(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider):
    """Tests that the generator fetches the secret from the provider on init."""
    # This test implicitly uses the 'generator' fixture, which runs the init
    generator(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider)
    
    # Verify the secret provider was called with the NAME from config
    mock_secret_provider.get_secret.assert_called_with("TEST_SIGNING_KEY")

def test_init_missing_secret_key_name(mock_vault, mock_guardrails, mock_logger, mock_secret_provider):
    """Tests init fails if config lacks the key NAME."""
    bad_config = {
        "MODEL_CACHE_DIR": "/tmp",
        "FOMM_CHECKPOINT_PATH": "/mock/fomm.pth"
    }
    with pytest.raises(ValueError, match="Config is missing 'PROVENANCE_SIGNING_KEY_NAME'"):
        SyntheticMediaGenerator(mock_vault, mock_guardrails, mock_logger, bad_config, mock_secret_provider)

def test_init_provider_returns_none(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider):
    """Tests init fails if the provider doesn't find the secret."""
    mock_secret_provider.get_secret.return_value = None
    with pytest.raises(ValueError, match="secret key 'TEST_SIGNING_KEY' is invalid"):
        SyntheticMediaGenerator(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider)

def test_init_secret_key_hardening(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider):
    """Tests that the generator fails if the secret key is invalid (too short)."""
    mock_secret_provider.get_secret.return_value = "short" # < 16 chars
    with pytest.raises(ValueError, match="secret key 'TEST_SIGNING_KEY' is invalid"):
        SyntheticMediaGenerator(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider)
    
    mock_secret_provider.get_secret.return_value = "" # Empty
    with pytest.raises(ValueError, match="secret key 'TEST_SIGNING_KEY' is invalid"):
        SyntheticMediaGenerator(mock_vault, mock_guardrails, mock_logger, mock_config, mock_secret_provider)

def test_env_secret_provider(monkeypatch):
    """Tests the real EnvSecretProvider."""
    monkeypatch.setenv("MY_TEST_KEY", "my_secret_value")
    provider = EnvSecretProvider()
    
    assert provider.get_secret("MY_TEST_KEY") == "my_secret_value"
    
    with pytest.raises(ValueError, match="Missing required secret: NONEXISTENT_KEY"):
        provider.get_secret("NONEXISTENT_KEY")


def test_jwt_payload_decode_helper():
    """Tests the _decode_jwt_payload helper for Base64URL."""
    # Mock JWT: header.payload.sig
    # Payload: {"sub": "123", "iat": 1516239022}
    payload_b64u = "eyJzdWIiOiAiMTIzIiwgImlhdCI6IDE1MTYyMzkwMjJ9"
    mock_token = f"xxxxx.{payload_b64u}.yyyyy"
    
    payload = _decode_jwt_payload(mock_token)
    
    assert payload["sub"] == "123"
    assert payload["iat"] == 1516239022

def test_request_voice_clone_text_too_long(generator, voice_consent):
    """Tests that a request fails if the target text is too long."""
    long_text = "a" * (TTS_MAX_LENGTH + 1)
    
    with pytest.raises(ValueError, match=f"Target text exceeds max length of {TTS_MAX_LENGTH}"):
        generator.request_synthetic_media(
            operator_id="op-001", use_case=AllowedUseCase.MARKETING,
            generation_type=GenerationType.VOICE_CLONE,
            consent_id=voice_consent.consent_id,
            target_text=long_text
        )

def test_execute_generation_face_reenactment_video_output(generator, face_consent, mock_vault):
    """Tests the full pipeline for face reenactment, now outputting video."""
    req = generator.request_synthetic_media(
        operator_id="op-001", use_case=AllowedUseCase.FILM_ADVERTISING,
        generation_type=GenerationType.FACE_REENACTMENT,
        consent_id=face_consent.consent_id,
        source_media_vault_id="vault:src-img-1",
        driving_media_vault_id="vault:drv-vid-1"
    )
    generator.approve_request("approver-001", req.request_id)
    
    asset = generator.execute_generation(req.request_id)
    
    # --- Check new video pipeline ---
    assert asset.generation_type == GenerationType.FACE_REENACTMENT
    assert asset.vault_file_path.endswith(".mp4")
    
    # Verify runtime was called
    mock_vault.read_artifact_bytes.assert_any_call("vault:src-img-1")
    mock_vault.read_artifact_bytes.assert_any_call("vault:drv-vid-1")
    generator.runtime.perform_face_reenactment.assert_called_once()
    
    # Verify video-specific provenance (no LSB)
    generator.provenance.sign_metadata.assert_called_once()
    generator.provenance.embed_provenance.assert_not_called() # No image LSB
    
    # Verify vault storage
    mock_vault.store_artifact_bytes.assert_called_with(
        data_bytes=b"mock_mp4_video_bytes",
        destination_path=asset.vault_file_path,
        description=ANY,
        tags=["synthetic", "generated", "video", "film_advertising_with_rights"]
    )
    assert mock_vault.store_json.call_count == 2 # request.json + provenance.json

def test_execute_generation_logs_jwt_to_debug(generator, face_consent, mock_logger):
    """Tests that the decoded JWT is logged to DEBUG, not INFO."""
    req = generator.request_synthetic_media(
        operator_id="op-001", use_case=AllowedUseCase.SYNTHETIC_SPOKESPERSON,
        generation_type=GenerationType.FULLY_SYNTHETIC_FACE,
        consent_id=face_consent.consent_id,
        generation_prompt="A face"
    )
    generator.approve_request("approver-001", req.request_id)
    
    asset = generator.execute_generation(req.request_id)
    
    # Check that it was logged to the vault
    generator.vault.store_json.assert_any_call(
        data={"decoded": "payload"},
        destination_path=f"forensic_records/{req.request_id}/provenance_metadata.json",
        description=ANY
    )
    
    # Check that it was logged to DEBUG
    mock_logger.debug.assert_any_call("Stored decoded provenance in vault: {'decoded': 'payload'}")


# --- Test Watermarking (Real) ---

@pytest.fixture
def real_provenance():
    return ProvenanceTools(secret_key="a-real-secret-key-for-lsb-123456")

@pytest.fixture
def test_image_rgba():
    """A test image with an Alpha channel."""
    return Image.new('RGBA', (100, 100), color=(255, 0, 0, 128))

@pytest.fixture
def test_wav_bytes_16bit_pcm():
    """Generates a dummy 16-bit PCM WAV file bytes."""
    header = (
        b'RIFF' + struct.pack('<I', 36 + 1024) + b'WAVE' + b'fmt ' +
        struct.pack('<I', 16) + struct.pack('<H', 1) +  # PCM
        struct.pack('<H', 1) + struct.pack('<I', 22050) +
        struct.pack('<I', 22050 * 2) + struct.pack('<H', 2) +
        struct.pack('<H', 16) + b'data' + struct.pack('<I', 1024) # 16-bit
    )
    data = b'\x00' * 1024
    return header + data

@pytest.fixture
def test_wav_bytes_32bit_float():
    """Generates a dummy 32-bit Float WAV file bytes (unsupported)."""
    header = (
        b'RIFF' + struct.pack('<I', 36 + 1024) + b'WAVE' + b'fmt ' +
        struct.pack('<I', 16) + struct.pack('<H', 3) +  # Float
        struct.pack('<H', 1) + struct.pack('<I', 22050) +
        struct.pack('<I', 22050 * 4) + struct.pack('<H', 4) +
        struct.pack('<H', 32) + b'data' + struct.pack('<I', 1024) # 32-bit
    )
    data = b'\x00' * 1024
    return header + data

def test_image_lsb_hardening(real_provenance, test_image_rgba):
    """Tests that LSB watermarking works on an RGBA image (by converting it)."""
    watermarker = real_provenance.neural_watermarker
    data = "test_rgba_embed"
    
    embedded_image = watermarker.embed(test_image_rgba, data)
    assert embedded_image.mode == "RGB"
    detected_data = watermarker.detect(embedded_image)
    assert detected_data == data

def test_audio_lsb_hardening_success(real_provenance, test_wav_bytes_16bit_pcm):
    """Tests that LSB audio watermarking SUCCEEDS on 16-bit PCM."""
    watermarker = real_provenance.audio_watermarker
    data = "test_good_audio"
    embedded_audio = watermarker.embed(test_wav_bytes_16bit_pcm, data)
    assert embedded_audio != test_wav_bytes_16bit_pcm
    detected_data = watermarker.detect(embedded_audio)
    assert detected_data == data

def test_audio_lsb_hardening_failure(real_provenance, test_wav_bytes_32bit_float):
    """Tests that LSB audio watermarking SKIPS unsupported formats (32-bit float)."""
    watermarker = real_provenance.audio_watermarker
    data = "test_bad_audio"
    embedded_audio = watermarker.embed(test_wav_bytes_32bit_float, data)
    assert embedded_audio == test_wav_bytes_32bit_float
    detected_data = watermarker.detect(embedded_audio)
    assert detected_data is None