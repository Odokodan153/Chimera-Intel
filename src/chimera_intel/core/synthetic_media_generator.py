# src/chimera_intel/core/synthetic_media_generator.py

import logging
import enum
import uuid
import json
import io
import hashlib
import struct  # For audio LSB
import tempfile
import os
import base64
from abc import ABC, abstractmethod
from datetime import datetime, timezone
# --- FIX: Import TYPE_CHECKING ---
from typing import Optional, Dict, Any, TYPE_CHECKING
# --- END FIX ---
from pydantic import Field
from jose import jwt, JWSAlgorithm
from jose.exceptions import JOSEError
from tenacity import retry, wait_exponential, stop_after_attempt, RetryError

# --- FIX: Add missing PIL imports ---
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
# --- END FIX ---

# ML/Gen libraries
try:
    import torch
    from diffusers import StableDiffusionPipeline, DPMSolverMultistepScheduler
    import numpy as np
    import cv2 # For video/frame processing
    from TTS.api import TTS
    import whisper
    
    try:
        from fomm.modules.generator import OcclusionAwareGenerator
        from fomm.modules.keypoint_detector import KPDetector
        from fomm.animate import normalize_kp
        from skimage.transform import resize
        from skimage import img_as_float32
    except ImportError:
        logging.warning("FOMM libraries (fomm, skimage) not found. Reenactment will fail.")
        class OcclusionAwareGenerator: pass
        class KPDetector: pass
        def normalize_kp(*args, **kwargs):
            device = "cuda" if torch.cuda.is_available() else "cpu"
            return {'value': torch.tensor(0, device=device), 'jacobian': torch.tensor(0, device=device)}
        def resize(img, size):
            return np.zeros(size + (img.shape[2],))
        def img_as_float32(img): 
            return np.array(img).astype(np.float32) / 255.0

except ImportError:
    logging.warning("Core ML libraries (diffusers, numpy, cv2, TTS, whisper) not installed.")
    # Define dummy classes for all ML components
    class DummyPipeline:
        def __init__(self, *args, **kwargs): pass
        def __call__(self, *args, **kwargs): raise ImportError("diffusers not found")
        def scheduler(self): pass
        def to(self, *args, **kwargs): return self
    class DummyTTS:
        def __init__(self, *args, **kwargs): pass
        def tts_to_file(self, *args, **kwargs): raise ImportError("TTS not found")
    class DummyWhisper:
        def __init__(self, *args, **kwargs): pass
        def load_model(self, *args, **kwargs): return self
        def transcribe(self, *args, **kwargs): return {"text": ""}
    
    StableDiffusionPipeline = DummyPipeline # type: ignore
    DPMSolverMultistepScheduler = object
    class DummyTorch:
        def __getattr__(self, name):
            if name == "cuda": return type('cuda', (object,), {'is_available': lambda: False})()
            if name == "tensor": return lambda *args, **kwargs: None
            return lambda *args, **kwargs: self
    torch = DummyTorch()
    np = object; cv2 = object; TTS = DummyTTS # type: ignore
    whisper = DummyWhisper()
    OcclusionAwareGenerator = DummyPipeline # type: ignore
    KPDetector = DummyPipeline # type: ignore
    normalize_kp = lambda *args, **kwargs: None
    resize = lambda *args, **kwargs: None
    img_as_float32 = lambda img: None


# --- FIX: Add TYPE_CHECKING block for lint-time-only imports ---
if TYPE_CHECKING:
    from diffusers import StableDiffusionPipeline
    from TTS.api import TTS
# --- END FIX ---


# Imports from existing Chimera-Intel modules
from .forensic_vault import ForensicVault
from .ethical_guardrails import EthicalGuardrails, DisallowedUseCaseError
from .audit_logger import AuditLogger
from .schemas import BaseChimeraModel

# Configure logging
logger = logging.getLogger(__name__)

# --- Constants ---
TTS_MAX_LENGTH = 500 # Max characters for voice clone request

# --- Enums and Schemas ---

class GenerationType(str, enum.Enum):
    """Specifies the type of synthetic media to generate."""
    FULLY_SYNTHETIC_FACE = "fully_synthetic_face"
    FACE_REENACTMENT = "face_reenactment"
    VOICE_CLONE = "voice_clone"

class AllowedUseCase(str, enum.Enum):
    """Enumerates the allowed use cases for generation."""
    MARKETING = "marketing_assets_with_consent"
    SYNTHETIC_SPOKESPERSON = "synthetic_spokesperson_stock"
    FILM_ADVERTISING = "film_advertising_with_rights"
    ANONYMIZATION = "anonymization_for_privacy"
    ML_AUGMENTATION = "ml_data_augmentation"

class RequestStatus(str, enum.Enum):
    """Tracks the status of a generation request."""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"

class ConsentArtifact(BaseChimeraModel):
    """Represents a verified consent document."""
    consent_id: str = Field(default_factory=lambda: f"consent-{uuid.uuid4()}")
    subject_name: str
    document_vault_id: str 
    identity_verified: bool = False
    voice_consent_phrase: Optional[str] = Field(None, description="A specific phrase to be spoken in consent audio for verification.")
    source_audio_vault_id: Optional[str] = Field(None, description="Vault ID of the audio used for consent verification and cloning.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SyntheticMediaRequest(BaseChimeraModel):
    """A request to generate synthetic media, pending approval."""
    request_id: str = Field(default_factory=lambda: f"synreq-{uuid.uuid4()}")
    operator_id: str
    use_case: AllowedUseCase
    generation_type: GenerationType
    consent_id: str 
    generation_prompt: Optional[str] = None 
    target_text: Optional[str] = None       
    source_media_vault_id: Optional[str] = None 
    driving_media_vault_id: Optional[str] = None
    status: RequestStatus = RequestStatus.PENDING_APPROVAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approver_id: Optional[str] = None
    approved_at: Optional[datetime] = None

class ProvenanceMetadata(BaseChimeraModel):
    """Signed metadata to be embedded in the generated asset."""
    iss: str = "Chimera-Intel-Platform"
    iat: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str
    asset_id: str
    model_version: str
    generation_type: GenerationType
    generation_params: Dict[str, Any]
    consent_id: str
    operator_id: str
    usage_license: str

class GeneratedAsset(BaseChimeraModel):
    """Represents the final, generated asset."""
    asset_id: str = Field(default_factory=lambda: f"synasset-{uuid.uuid4()}")
    request_id: str
    vault_file_path: str 
    provenance_jwt: str 
    detection_fingerprint: str 

# --- Security Abstraction ---

class SecretProvider(ABC):
    """Abstracts the retrieval of secrets (e.g., from env vars, KMS, Vault)."""
    @abstractmethod
    def get_secret(self, secret_name: str) -> str:
        """Retrieves a secret string by its name."""
        pass

class EnvSecretProvider(SecretProvider):
    """Retrieves secrets from environment variables."""
    def get_secret(self, secret_name: str) -> str:
        secret_value = os.environ.get(secret_name)
        if not secret_value:
            logger.error(f"Secret '{secret_name}' not found in environment variables.")
            raise ValueError(f"Missing required secret: {secret_name}")
        return secret_value

# --- Helper Classes (Hardened) ---

class _NeuralWatermarker:
    """Implements robust invisible watermark using LSB (Least Significant Bit)."""
    
    def __init__(self):
        self.delimiter = "::CHIMERA::"

    def _str_to_bin(self, data: str) -> str:
        """Convert a string to a binary string."""
        return ''.join(format(ord(i), '08b') for i in data)

    def _bin_to_str(self, binary: str) -> str:
        """Convert a binary string back to a string."""
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

    def embed(self, image: Image.Image, data: str) -> Image.Image:
        """Embeds data into the LSB of the image pixels."""
        if image.mode != "RGB":
            image = image.convert("RGB")
        data_to_embed = data + self.delimiter
        binary_data = self._str_to_bin(data_to_embed) + '1111111111111110' # End marker
        if len(binary_data) > image.width * image.height * 3:
            raise ValueError("Data is too large to embed in this image.")
        new_img = image.copy()
        pixels = new_img.load()
        data_idx = 0
        for y in range(new_img.height):
            for x in range(new_img.width):
                if data_idx < len(binary_data):
                    r, g, b = pixels[x, y]
                    if data_idx < len(binary_data):
                        r = (r & 0xFE) | int(binary_data[data_idx])
                        data_idx += 1
                    if data_idx < len(binary_data):
                        g = (g & 0xFE) | int(binary_data[data_idx])
                        data_idx += 1
                    if data_idx < len(binary_data):
                        b = (b & 0xFE) | int(binary_data[data_idx])
                        data_idx += 1
                    pixels[x, y] = (r, g, b)
                else:
                    return new_img
        return new_img

    def detect(self, image: Image.Image) -> Optional[str]:
        """Detects and extracts LSB-embedded data from an image."""
        if image.mode != "RGB":
            image = image.convert("RGB")
        pixels = image.load()
        binary_data = ""
        for y in range(image.height):
            for x in range(image.width):
                r, g, b = pixels[x, y]
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
                if binary_data.endswith('1111111111111110'):
                    binary_data = binary_data[:-16] # Remove end marker
                    try:
                        decoded_str = self._bin_to_str(binary_data)
                        if self.delimiter in decoded_str:
                            return decoded_str.split(self.delimiter)[0]
                    except Exception:
                        return None 
        return None

class _AudioWatermarker:
    """Implements a robust invisible audio watermark using LSB."""
    
    def __init__(self):
        self.delimiter = "::CHIMERA_AU::"

    def _str_to_bin(self, data: str) -> str:
        """Convert a string to a binary string."""
        return ''.join(format(ord(i), '08b') for i in data)

    def _bin_to_str(self, binary: str) -> str:
        """Convert a binary string back to a string."""
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

    def embed(self, wav_bytes: bytes, data: str) -> bytes:
        """Embeds data into the LSB of 16-bit PCM audio samples."""
        try:
            if wav_bytes[8:12] != b'WAVE' or wav_bytes[12:16] != b'fmt ':
                raise ValueError("Not a valid WAV file (missing WAVE/fmt).")
            audio_format = struct.unpack('<H', wav_bytes[20:22])[0]
            bits_per_sample = struct.unpack('<H', wav_bytes[34:36])[0]
            if audio_format != 1 or bits_per_sample != 16:
                raise ValueError(f"Audio is not 16-bit PCM. Format: {audio_format}, Bits: {bits_per_sample}")
        except Exception as e:
            logger.warning(f"Audio LSB watermarking skipped: {e}")
            return wav_bytes # Return original, unmodified bytes
        
        data_to_embed = data + self.delimiter
        binary_data = self._str_to_bin(data_to_embed) + '1111111111111110' # End marker
        data_chunk_pos = wav_bytes.find(b'data')
        if data_chunk_pos == -1:
            raise ValueError("Invalid WAV file: 'data' chunk not found.")
            
        data_start_pos = data_chunk_pos + 8
        header = bytearray(wav_bytes[:data_start_pos])
        samples = bytearray(wav_bytes[data_start_pos:])
        
        if len(binary_data) > len(samples) // 2: # Each bit goes into one sample (of 2 bytes)
            raise ValueError("Data is too large to embed in this audio file.")
            
        data_idx = 0
        # Embed in LSB of the *second* byte of each 16-bit sample
        for i in range(1, len(samples), 2): 
            if data_idx < len(binary_data):
                sample_byte = samples[i]
                modified_byte = (sample_byte & 0xFE) | int(binary_data[data_idx])
                samples[i] = modified_byte
                data_idx += 1
            else:
                break
        
        return bytes(header + samples)

    def detect(self, wav_bytes: bytes) -> Optional[str]:
        """Detects and extracts LSB-embedded data from audio."""
        data_chunk_pos = wav_bytes.find(b'data')
        if data_chunk_pos == -1: return None
        data_start_pos = data_chunk_pos + 8
        samples = wav_bytes[data_start_pos:]
        binary_data = ""
        # Read from LSB of the *second* byte of each 16-bit sample
        for i in range(1, len(samples), 2):
            sample_byte = samples[i]
            binary_data += str(sample_byte & 1)
            
            if len(binary_data) % 8 == 0 and binary_data.endswith('1111111111111110'):
                binary_data = binary_data[:-16]
                try:
                    decoded_str = self._bin_to_str(binary_data)
                    if self.delimiter in decoded_str:
                        return decoded_str.split(self.delimiter)[0]
                except Exception as e:
                    logger.warning(f"Audio LSB decoding error: {e}")
                    return None
        return None

class ProvenanceTools:
    """Handles watermarking and cryptographic signing of metadata."""

    def __init__(self, secret_key: str, algorithm: str = JWSAlgorithm.HS256):
        if not secret_key:
            raise ValueError("A secret_key is required for signing provenance data.")
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.visible_watermark_text = "SYNTHETIC MEDIA (Chimera-Intel)"
        self.neural_watermarker = _NeuralWatermarker() # Image LSB
        self.audio_watermarker = _AudioWatermarker() # Audio LSB
        try:
            self.font = ImageFont.load_default()
        except IOError:
            logger.warning("Default PIL font not found. Visible watermark will be basic.")
            self.font = None
    
    def sign_metadata(self, metadata: ProvenanceMetadata) -> str:
        """Signs the provenance metadata into a secure JWT."""
        try:
            payload = metadata.dict()
            payload['iat'] = payload['iat'].isoformat()
            return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        except JOSEError as e:
            logger.error(f"Failed to sign provenance metadata: {e}")
            raise

    def embed_provenance(self, image: Image.Image, provenance_jwt: str) -> Image.Image:
        """Embeds provenance into an image (Visible, Metadata, and LSB)."""
        draw = ImageDraw.Draw(image)
        try:
            text_width, text_height = draw.textbbox((0,0), self.visible_watermark_text, font=self.font)[2:]
        except:
            text_width, text_height = (100, 10) # Fallback
        position = (image.width - text_width - 10, image.height - text_height - 10)
        draw.rectangle((position[0]-5, position[1]-5, position[0]+text_width+5, position[1]+text_height+5), fill=(0,0,0,64))
        draw.text(position, self.visible_watermark_text, fill=(255, 255, 255, 128), font=self.font)
        image.info["ChimeraIntelProvenance"] = provenance_jwt
        
        try:
            image = self.neural_watermarker.embed(image, provenance_jwt)
        except Exception as e:
            logger.warning(f"Failed to embed LSB watermark: {e}. Relying on metadata only.")
        return image

    def read_provenance(self, image: Image.Image) -> Optional[Dict[str, Any]]:
        """Reads provenance from image (LSB first, then metadata)."""
        try:
            jwt_lsb = self.neural_watermarker.detect(image)
            if jwt_lsb:
                logger.info("Detected provenance from LSB watermark.")
                return jwt.decode(jwt_lsb, self.secret_key, algorithms=[self.algorithm])
        except Exception as e:
            logger.warning(f"Failed to read/verify LSB watermark: {e}. Checking metadata.")
        try:
            jwt_meta = image.info.get("ChimeraIntelProvenance")
            if jwt_meta:
                logger.info("Detected provenance from metadata watermark.")
                return jwt.decode(jwt_meta, self.secret_key, algorithms=[self.algorithm])
        except Exception as e:
            logger.warning(f"Failed to read or verify metadata provenance: {e}")
        return None

    def embed_audio_provenance(self, audio_bytes: bytes, provenance_jwt: str) -> bytes:
        """Embeds provenance into audio bytes using LSB."""
        try:
            logger.info("Embedding robust LSB watermark into audio samples.")
            return self.audio_watermarker.embed(audio_bytes, provenance_jwt)
        except Exception as e:
            logger.warning(f"Failed to embed LSB audio watermark: {e}. Asset will not be watermarked.")
            return audio_bytes # Return original bytes

    def read_audio_provenance(self, audio_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Reads and verifies embedded provenance from audio bytes."""
        try:
            jwt_lsb = self.audio_watermarker.detect(audio_bytes)
            if jwt_lsb:
                logger.info("Detected provenance from audio LSB watermark.")
                return jwt.decode(jwt_lsb, self.secret_key, algorithms=[self.algorithm])
        except Exception as e:
            logger.warning(f"Failed to read/verify audio LSB watermark: {e}")
        return None

def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Correctly decodes a JWT payload from Base64URL."""
    try:
        payload_b64u = token.split('.')[1]
        payload_b64 = payload_b64u + '=' * (-len(payload_b64u) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded_payload)
    except Exception as e:
        logger.error(f"JWT decode error: {e}")
        return {"error": "decoding_failed"}

# --- Real ML Runtime (with Retries) ---

# Define retry strategy for transient ML failures
ml_retry_strategy = retry(
    wait=wait_exponential(multiplier=1, min=2, max=30), # 1s, 2s, 4s...
    stop=stop_after_attempt(3), # Max 3 attempts
    reraise=True # Reraise the last exception if all retries fail
)

class IsolatedGenerationRuntime:
    """Wraps the actual ML models for generation."""
    
    def __init__(self, model_cache_dir: str, fomm_checkpoint_path: Optional[str]):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Initializing IsolatedGenerationRuntime on device: {self.device}")
        
        self.model_cache_dir = model_cache_dir
        self.fomm_checkpoint_path = fomm_checkpoint_path
        
        # Load models on init (as you noted, this is the caching)
        # --- FIX: Use string forward-references to satisfy linters ---
        self.face_gen_pipeline: Any  = self._load_face_gen_model("SG161222/Realistic_Vision_V5.1_no_VAE")
        self.stt_model = self._load_stt_model()
        self.tts_model: Any = self._load_voice_model()
        # --- END FIX ---
        self.fomm_generator, self.fomm_kp_detector = self._load_reenactment_model()

    # --- FIX: Use string forward-references to satisfy linters ---
    def _load_face_gen_model(self, model_id: str) -> Any:
    # --- END FIX ---
        try:
            pipe = StableDiffusionPipeline.from_pretrained(
                model_id, 
                torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
                cache_dir=self.model_cache_dir
            )
            pipe.scheduler = DPMSolverMultistepScheduler.from_config(pipe.scheduler.config)
            pipe = pipe.to(self.device)
            logger.info(f"Loaded face gen model {model_id} on {self.device}")
            return pipe
        except Exception as e:
            logger.error(f"Failed to load SD model {model_id}: {e}")
            return DummyPipeline() # type: ignore

    def _load_stt_model(self):
        try:
            model = whisper.load_model("tiny.en")
            logger.info("Loaded STT model (Whisper).")
            return model
        except Exception as e:
            logger.error(f"Failed to load STT model: {e}")
            return DummyWhisper()

    # --- FIX: Use string forward-references to satisfy linters ---
    def _load_voice_model(self) -> Any:
    # --- END FIX ---
        try:
            model = TTS(model_name="tts_models/en/vctk/vits", progress_bar=False).to(self.device)
            logger.info("Loaded REAL speaker-adaptive TTS model (VITS).")
            return model
        except Exception as e:
            logger.error(f"Failed to load REAL TTS model: {e}")
            return DummyTTS() # type: ignore

    def _load_reenactment_model(self):
        """Loads the REAL FOMM model components from checkpoint."""
        try:
            if not self.fomm_checkpoint_path or not os.path.exists(self.fomm_checkpoint_path):
                raise FileNotFoundError(f"FOMM checkpoint not found or not specified: {self.fomm_checkpoint_path}")

            logger.info(f"Loading FOMM models from checkpoint: {self.fomm_checkpoint_path}")
            checkpoint = torch.load(self.fomm_checkpoint_path, map_location=self.device)
            
            generator = OcclusionAwareGenerator(**checkpoint['config']['model_params']['generator_params'],
                                                **checkpoint['config']['model_params']['common_params'])
            generator.load_state_dict(checkpoint['generator'])
            generator.to(self.device)
            generator.eval()

            kp_detector = KPDetector(**checkpoint['config']['model_params']['kp_detector_params'],
                                     **checkpoint['config']['model_params']['common_params'])
            kp_detector.load_state_dict(checkpoint['kp_detector'])
            kp_detector.to(self.device)
            kp_detector.eval()
            
            logger.info("Loaded REAL FOMM models (Generator, KPDetector).")
            return generator, kp_detector
            
        except Exception as e:
            logger.error(f"Failed to load REAL FOMM models: {e}. Reenactment will fail.")
            return DummyPipeline(), DummyPipeline()

    @ml_retry_strategy
    def generate_synthetic_face(self, prompt: str, num_steps: int = 25) -> Image.Image:
        logger.debug("Attempting to generate synthetic face...")
        negative_prompt = "celebrity, real person, named person, likeness, blurry, ugly"
        guidance = "A studio portrait of a synthetic person, stock photo, 4k"
        full_prompt = f"{prompt}, {guidance}"
        try:
            return self.face_gen_pipeline(
                prompt=full_prompt, 
                negative_prompt=negative_prompt, 
                num_inference_steps=num_steps,
            ).images[0]
        except Exception as e:
            logger.warning(f"Face generation attempt failed: {e}")
            raise

    @ml_retry_strategy
    def perform_face_reenactment(self, source_image_bytes: bytes, driving_video_bytes: bytes) -> bytes:
        """Performs REAL talking-head transfer. Returns .mp4 bytes."""
        logger.debug("Attempting to perform face reenactment...")
        
        if isinstance(self.fomm_generator, DummyPipeline):
             raise RuntimeError("Cannot perform reenactment: FOMM models not loaded.")

        temp_video_path = None
        temp_out_path = None
        video_cap = None
        out_writer = None
        
        try:
            # 1. Load source image
            source_np = cv2.imdecode(np.frombuffer(source_image_bytes, np.uint8), cv2.IMREAD_COLOR)
            source_np = cv2.cvtColor(source_np, cv2.COLOR_BGR2RGB)
            source_resized = resize(source_np, (256, 256))[..., :3]
            source_tensor = torch.tensor(img_as_float32(source_resized)).permute(2, 0, 1).unsqueeze(0).to(self.device)

            # 2. Save driving video to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as temp_video:
                temp_video.write(driving_video_bytes)
                temp_video_path = temp_video.name
            
            video_cap = cv2.VideoCapture(temp_video_path)
            # --- HARDENING ---
            if not video_cap.isOpened():
                raise RuntimeError(f"Failed to open driving video at {temp_video_path}")
            # --- END HARDENING ---

            # --- Setup video output ---
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as temp_out:
                temp_out_path = temp_out.name
                
            fps = video_cap.get(cv2.CAP_PROP_FPS)
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out_writer = cv2.VideoWriter(temp_out_path, fourcc, fps, (256, 256))
            # --- HARDENING ---
            if not out_writer.isOpened():
                raise RuntimeError("Failed to open VideoWriter. Check codec (mp4v) and permissions.")
            # --- END HARDENING ---

            # 3. Get keypoints from source
            with torch.no_grad():
                kp_source = self.fomm_kp_detector(source_tensor)

            # 4. Iterate through driving video frames
            frame_count = 0
            while video_cap.isOpened():
                ret, driving_frame_np = video_cap.read()
                if not ret:
                    break
                
                frame_count += 1
                driving_frame_np = cv2.cvtColor(driving_frame_np, cv2.COLOR_BGR2RGB)
                driving_resized = resize(driving_frame_np, (256, 256))[..., :3]
                driving_tensor = torch.tensor(img_as_float32(driving_resized)).permute(2, 0, 1).unsqueeze(0).to(self.device)

                # 5. Run inference per frame
                with torch.no_grad():
                    kp_driving = self.fomm_kp_detector(driving_tensor)
                    kp_norm = normalize_kp(kp_source=kp_source, kp_driving=kp_driving)
                    
                    generated_frame = self.fomm_generator(source_tensor, kp_source=kp_source, kp_driving=kp_norm)
                    
                    out_np = np.transpose(generated_frame['prediction'].data.cpu().numpy()[0], (1, 2, 0))
                    out_np = (out_np * 255).astype(np.uint8)
                    out_np = cv2.cvtColor(out_np, cv2.COLOR_RGB2BGR) # Convert back to BGR for VideoWriter
                    
                    out_writer.write(out_np)

            # 6. Release writers and read bytes
            video_cap.release()
            out_writer.release()
            video_cap = None # Mark as released
            out_writer = None # Mark as released
            
            if frame_count == 0:
                raise ValueError("Driving video was empty or unreadable.")

            with open(temp_out_path, "rb") as f:
                video_bytes = f.read()
            
            logger.info(f"Face reenactment (FOMM) successful. Generated {frame_count} frames.")
            return video_bytes
        
        except Exception as e:
            logger.warning(f"Face reenactment attempt failed: {e}")
            raise # Reraise for tenacity
        finally:
            # 7. Clean up temp files
            if video_cap and video_cap.isOpened():
                video_cap.release()
            if out_writer and out_writer.isOpened():
                out_writer.release()
            if temp_video_path and os.path.exists(temp_video_path):
                os.remove(temp_video_path)
            if temp_out_path and os.path.exists(temp_out_path):
                os.remove(temp_out_path)

    def verify_voice_consent(self, audio_file_path: str, required_phrase: str) -> bool:
        """Performs secondary verification using Whisper STT."""
        # (This is not a long ML inference task, so no retry)
        try:
            # Note: Whisper is robust to most formats/sample rates
            result = self.stt_model.transcribe(audio_file_path)
            transcribed_text = result["text"].strip()
            logger.info(f"Transcription: '{transcribed_text}'")
            return required_phrase.lower() in transcribed_text.lower()
        except Exception as e:
            logger.error(f"STT failed: {e}")
            return False

    @ml_retry_strategy
    def clone_voice(self, source_audio_path: str, target_text: str) -> bytes:
        """Clones a voice using Coqui TTS."""
        logger.debug("Attempting to clone voice...")
        
        if isinstance(self.tts_model, DummyTTS):
             raise RuntimeError("TTS model is not loaded. Cannot generate voice.")
            
        temp_wav_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_wav:
                temp_wav_path = temp_wav.name

            # 1. Call the REAL model
            self.tts_model.tts_to_file(
                text=target_text,
                speaker_wav=source_audio_path,
                file_path=temp_wav_path,
                language="en"
            )

            # 2. Read the generated bytes back
            if os.path.exists(temp_wav_path):
                with open(temp_wav_path, "rb") as f:
                    wav_bytes = f.read()
                return wav_bytes
            else:
                raise RuntimeError("TTS model failed to produce an output file.")
        except Exception as e:
            logger.warning(f"Voice clone attempt failed: {e}")
            raise # Reraise for tenacity
        finally:
            if temp_wav_path and os.path.exists(temp_wav_path):
                os.remove(temp_wav_path)


# --- Main Service Class (Security Hardened) ---

class SyntheticMediaGenerator:
    """Main service for managing the synthetic media generation pipeline."""

    def __init__(
        self,
        vault: ForensicVault,
        guardrails: EthicalGuardrails,
        logger: AuditLogger,
        config: Dict[str, Any],
        secret_provider: SecretProvider
    ):
        self.vault = vault
        self.guardrails = guardrails
        self.logger = logger
        
        try:
            key_name = config.get("PROVENANCE_SIGNING_KEY_NAME")
            if not key_name:
                raise ValueError("Config is missing 'PROVENANCE_SIGNING_KEY_NAME'")
            secret_key = secret_provider.get_secret(key_name)
            # --- HARDENING ---
            if not secret_key or not isinstance(secret_key, str) or len(secret_key) < 16:
                raise ValueError(f"Secret key '{key_name}' is invalid (empty or too short).")
            # --- END HARDENING ---
                
        except Exception as e:
            logger.critical(f"Failed to retrieve provenance signing key: {e}")
            raise

        model_cache = config.get("MODEL_CACHE_DIR", "./chimera_models/synthetic_media")
        fomm_path = config.get("FOMM_CHECKPOINT_PATH") # Can be None
        if not fomm_path:
            logger.warning("Config is missing 'FOMM_CHECKPOINT_PATH'. Reenactment will be disabled.")
        
        self.requests: Dict[str, SyntheticMediaRequest] = {}
        self.consents: Dict[str, ConsentArtifact] = {}
        
        self.provenance = ProvenanceTools(secret_key=secret_key)
        self.runtime = IsolatedGenerationRuntime(
            model_cache_dir=model_cache,
            fomm_checkpoint_path=fomm_path
        )
        logger.info("SyntheticMediaGenerator initialized (REAL models, security-hardened).")

    def register_consent(
        self, 
        subject_name: str, 
        document_vault_id: str, 
        identity_verified: bool,
        voice_consent_phrase: Optional[str] = None,
        source_audio_vault_id: Optional[str] = None
    ) -> ConsentArtifact:
        """Stores a record of verified consent."""
        if voice_consent_phrase and not source_audio_vault_id:
            raise ValueError("source_audio_vault_id is required if voice_consent_phrase is set.")
            
        consent = ConsentArtifact(
            subject_name=subject_name,
            document_vault_id=document_vault_id,
            identity_verified=identity_verified,
            voice_consent_phrase=voice_consent_phrase,
            source_audio_vault_id=source_audio_vault_id
        )
        self.consents[consent.consent_id] = consent
        self.logger.log_event(
            "synthetic_media_consent_registered",
            f"Consent {consent.consent_id} registered for {subject_name}",
            {"consent_id": consent.consent_id, "doc_id": document_vault_id, "has_voice": bool(voice_consent_phrase)}
        )
        return consent

    def request_synthetic_media(
        self,
        operator_id: str,
        use_case: AllowedUseCase,
        generation_type: GenerationType,
        consent_id: str,
        generation_prompt: Optional[str] = None,
        target_text: Optional[str] = None,
        source_media_vault_id: Optional[str] = None,
        driving_media_vault_id: Optional[str] = None
    ) -> SyntheticMediaRequest:
        """Step 1: Request Intake & Pre-check"""
        self.logger.log_event("synthetic_media_request_received", f"Request received from {operator_id}", {"operator_id": operator_id, "use_case": use_case})

        try:
            self.guardrails.check_synthetic_media_policy(
                use_case=use_case,
                generation_type=generation_type,
                operator_id=operator_id
            )
        except DisallowedUseCaseError as e:
            self.logger.log_security_event("synthetic_media_request_blocked", f"Request from {operator_id} blocked by guardrails.", {"reason": str(e)})
            raise
        
        if consent_id not in self.consents:
            raise ValueError(f"Consent ID {consent_id} not found or not registered.")
        
        if generation_type == GenerationType.FULLY_SYNTHETIC_FACE:
            if not generation_prompt:
                raise ValueError("generation_prompt is required for FULLY_SYNTHETIC_FACE")
        elif generation_type == GenerationType.FACE_REENACTMENT:
            if not source_media_vault_id or not driving_media_vault_id:
                raise ValueError("source_media_vault_id and driving_media_vault_id are required for FACE_REENACTMENT")
        elif generation_type == GenerationType.VOICE_CLONE:
            if not target_text:
                raise ValueError("target_text is required for VOICE_CLONE")
            # --- HARDENING ---
            if len(target_text) > TTS_MAX_LENGTH:
                raise ValueError(f"Target text exceeds max length of {TTS_MAX_LENGTH} characters.")
            # --- END HARDENING ---
            if not self.consents[consent_id].source_audio_vault_id:
                raise ValueError("Consent artifact is missing required source_audio_vault_id for voice cloning.")

        request = SyntheticMediaRequest(
            operator_id=operator_id,
            use_case=use_case,
            generation_type=generation_type,
            consent_id=consent_id,
            generation_prompt=generation_prompt,
            target_text=target_text,
            source_media_vault_id=source_media_vault_id,
            driving_media_vault_id=driving_media_vault_id,
        )
        
        self.requests[request.request_id] = request
        self.logger.log_event("synthetic_media_request_pending", f"Request {request.request_id} is pending approval.", {"request_id": request.request_id})
        return request

    def approve_request(self, approver_id: str, request_id: str) -> SyntheticMediaRequest:
        """Step 2: Human Approval & Secondary Verification"""
        if request_id not in self.requests:
            raise ValueError(f"Request ID {request_id} not found.")
        request = self.requests[request_id]

        if approver_id == request.operator_id:
            self.logger.log_security_event("synthetic_media_approval_failed", "Operator self-approval attempted.", {"request_id": request_id, "operator_id": approver_id})
            raise PermissionError("Operator cannot self-approve a generation request.")

        if request.generation_type == GenerationType.VOICE_CLONE:
            consent = self.consents[request.consent_id]
            if not consent.voice_consent_phrase:
                raise PermissionError(f"Cannot approve: Consent {consent.consent_id} is missing the required 'voice_consent_phrase'.")
            
            logger.info("Performing voice consent secondary verification...")
            audio_path = self.vault.get_local_path(consent.source_audio_vault_id) 
            
            is_verified = self.runtime.verify_voice_consent(
                audio_file_path=audio_path,
                required_phrase=consent.voice_consent_phrase
            )
            
            if not is_verified:
                request.status = RequestStatus.REJECTED
                self.logger.log_security_event("synthetic_media_approval_failed", "Voice consent secondary verification failed.", {"request_id": request_id})
                raise PermissionError(f"Voice consent verification failed: The phrase '{consent.voice_consent_phrase}' was not detected in the provided consent audio.")

        request.status = RequestStatus.APPROVED
        request.approver_id = approver_id
        request.approved_at = datetime.now(timezone.utc)
        
        self.logger.log_event("synthetic_media_request_approved", f"Request {request_id} approved by {approver_id}", {"request_id": request_id, "approver_id": approver_id})
        return request

    def _execute_image_generation(self, request: SyntheticMediaRequest) -> GeneratedAsset:
        """Handles FULLY_SYNTHETIC_FACE generation."""
        asset_id = f"synasset-{uuid.uuid4()}"
        raw_image = self.runtime.generate_synthetic_face(prompt=request.generation_prompt)
        
        provenance = ProvenanceMetadata(
            request_id=request.request_id, asset_id=asset_id,
            model_version="Realistic_Vision_V5.1", generation_type=request.generation_type,
            generation_params={"prompt": request.generation_prompt}, consent_id=request.consent_id,
            operator_id=request.operator_id, usage_license=f"Usage: {request.use_case.value}"
        )
        provenance_jwt = self.provenance.sign_metadata(provenance)
        final_image = self.provenance.embed_provenance(raw_image, provenance_jwt)

        asset_filename = f"{asset_id}.png"
        img_byte_arr = io.BytesIO()
        
        # --- HARDENING IMPLEMENTED ---
        try:
            # Filter info dict to only include string key/values for PngInfo
            png_info_dict = {k: v for k, v in final_image.info.items() if isinstance(k, str) and isinstance(v, str)}
            png_info = PngImagePlugin.PngInfo()
            for k, v in png_info_dict.items():
                png_info.add_text(k, v)
                
            final_image.save(img_byte_arr, format='PNG', pnginfo=png_info)
        except Exception as e:
            logger.warning(f"Failed to save with full PngInfo metadata: {e}. Saving without metadata.")
            # Fallback to saving without the info chunk
            final_image.save(img_byte_arr, format='PNG')
        # --- END HARDENING ---
        
        img_bytes = img_byte_arr.getvalue()
        
        vault_file_path = f"synthetic_assets/{asset_filename}"
        self.vault.store_artifact_bytes(
            data_bytes=img_bytes, destination_path=vault_file_path,
            description=f"Synthetic asset for {request.request_id}",
            tags=["synthetic", "generated", "image", request.use_case.value]
        )
        
        fingerprint = hashlib.sha256(img_bytes).hexdigest()
        return GeneratedAsset(
            asset_id=asset_id, request_id=request.request_id,
            vault_file_path=vault_file_path, provenance_jwt=provenance_jwt,
            detection_fingerprint=fingerprint
        )

    def _execute_video_generation(self, request: SyntheticMediaRequest) -> GeneratedAsset:
        """Handles FACE_REENACTMENT generation, outputting MP4."""
        asset_id = f"synasset-{uuid.uuid4()}"
        
        source_img_bytes = self.vault.read_artifact_bytes(request.source_media_vault_id)
        driving_video_bytes = self.vault.read_artifact_bytes(request.driving_media_vault_id)
        
        video_bytes = self.runtime.perform_face_reenactment(source_img_bytes, driving_video_bytes)
        
        generation_params = {
            "source": request.source_media_vault_id,
            "driving_hash": hashlib.sha256(driving_video_bytes).hexdigest()
        }
        provenance = ProvenanceMetadata(
            request_id=request.request_id, asset_id=asset_id,
            model_version="FOMM_v1.0", generation_type=request.generation_type,
            generation_params=generation_params, consent_id=request.consent_id,
            operator_id=request.operator_id, usage_license=f"Usage: {request.use_case.value}"
        )
        provenance_jwt = self.provenance.sign_metadata(provenance)

        asset_filename = f"{asset_id}.mp4"
        vault_file_path = f"synthetic_assets/{asset_filename}"
        self.vault.store_artifact_bytes(
            data_bytes=video_bytes, destination_path=vault_file_path,
            description=f"Synthetic video asset for {request.request_id}",
            tags=["synthetic", "generated", "video", request.use_case.value]
        )
        
        fingerprint = hashlib.sha256(video_bytes).hexdigest()
        return GeneratedAsset(
            asset_id=asset_id, request_id=request.request_id,
            vault_file_path=vault_file_path, provenance_jwt=provenance_jwt,
            detection_fingerprint=fingerprint
        )

    def _execute_audio_generation(self, request: SyntheticMediaRequest) -> GeneratedAsset:
        """Handles VOICE_CLONE generation."""
        asset_id = f"synasset-{uuid.uuid4()}"
        audio_path = self.vault.get_local_path(self.consents[request.consent_id].source_audio_vault_id)
        
        raw_audio_bytes = self.runtime.clone_voice(audio_path, request.target_text)

        provenance = ProvenanceMetadata(
            request_id=request.request_id, asset_id=asset_id,
            model_version="Coqui_TTS_VITS_v1.0", generation_type=request.generation_type,
            generation_params={"target_text": request.target_text}, consent_id=request.consent_id,
            operator_id=request.operator_id, usage_license=f"Usage: {request.use_case.value}"
        )
        provenance_jwt = self.provenance.sign_metadata(provenance)
        final_audio_bytes = self.provenance.embed_audio_provenance(raw_audio_bytes, provenance_jwt)

        asset_filename = f"{asset_id}.wav"
        vault_file_path = f"synthetic_assets/{asset_filename}"
        self.vault.store_artifact_bytes(
            data_bytes=final_audio_bytes, destination_path=vault_file_path,
            description=f"Synthetic audio asset for {request.request_id}",
            tags=["synthetic", "generated", "audio", request.use_case.value]
        )
        
        fingerprint = hashlib.sha256(final_audio_bytes).hexdigest()
        return GeneratedAsset(
            asset_id=asset_id, request_id=request.request_id,
            vault_file_path=vault_file_path, provenance_jwt=provenance_jwt,
            detection_fingerprint=fingerprint
        )

    def execute_generation(self, request_id: str) -> GeneratedAsset:
        """Steps 3-6: Generation, Watermarking, Forensic Record, Delivery"""
        if request_id not in self.requests:
            raise ValueError(f"Request ID {request_id} not found")
        request = self.requests[request_id]
        if request.status != RequestStatus.APPROVED:
            raise PermissionError(f"Request {request_id} is not APPROVED")

        try:
            request.status = RequestStatus.GENERATING
            
            if request.generation_type == GenerationType.FULLY_SYNTHETIC_FACE:
                asset = self._execute_image_generation(request)
            elif request.generation_type == GenerationType.FACE_REENACTMENT:
                asset = self._execute_video_generation(request)
            elif request.generation_type == GenerationType.VOICE_CLONE:
                asset = self._execute_audio_generation(request)
            else:
                raise NotImplementedError(f"Unknown generation type {request.generation_type}")

            # Store forensic records
            self.vault.store_json(
                data=request.dict(),
                destination_path=f"forensic_records/{request_id}/request.json",
                description="Generation request record"
            )
            decoded_payload = _decode_jwt_payload(asset.provenance_jwt)
            
            # --- SECURE LOGGING ---
            self.vault.store_json(
                data=decoded_payload,
                destination_path=f"forensic_records/{request_id}/provenance_metadata.json",
                description="Generation provenance record (decoded)"
            )
            logger.debug(f"Stored decoded provenance in vault: {decoded_payload}")
            # --- END SECURE LOGGING ---
            
            request.status = RequestStatus.COMPLETED
            self.logger.log_event(
                "generation_complete", f"Asset {asset.asset_id} generated.",
                {"id": asset.asset_id, "req_id": request_id, "fp": asset.detection_fingerprint}
            )
            return asset

        except (RetryError, Exception) as e: # Catch RetryError from tenacity
            request.status = RequestStatus.FAILED
            logger.error(f"Generation failed permanently for request {request_id}: {e}")
            self.logger.log_event("generation_failed", f"Generation failed for {request_id}", {"id": request_id, "err": str(e)})
            raise