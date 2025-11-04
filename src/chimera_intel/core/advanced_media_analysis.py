"""
Chimera-Intel Advanced Media Analysis Module (Heuristic-Based)
===============================================================

This module provides sophisticated analysis of media files to detect
forensic artifacts, deepfakes, AI generation, and content provenance.

It uses a heuristic-based approach and does NOT require external AI models.
It also defines its own Typer-based CLI commands.

Dependencies:
- opencv-python-headless, opencv-contrib-python-headless
- numpy, Pillow, scikit-image, librosa, c2pa
- typer, rich
"""

import logging
import json
import subprocess
import io
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import os
import math
from PIL import Image, ImageChops
# --- CLI & Utility Imports ---
try:
    import typer
    from typing_extensions import Annotated
    from rich.console import Console
    from rich.json import JSON
except ImportError:
    print("ERROR: Missing CLI dependencies. Please run: pip install typer rich")
    raise

# --- Analysis Imports ---
try:
    import cv2
    import numpy as np
    from PIL import Image, ImageChops
    from skimage.restoration import denoise_wavelet, estimate_sigma
    from skimage import io as skio
    from skimage.util import img_as_float
except ImportError:
    print("ERROR: Missing dependencies. Please run: pip install opencv-python-headless opencv-contrib-python-headless numpy Pillow scikit-image")
    raise
try:
    import librosa
except ImportError:
    print("ERROR: Missing 'librosa'. Please run: pip install librosa")
    raise
try:
    import c2pa
    from c2pa.exceptions import C2paError
except ImportError:
    print("ERROR: Missing 'c2pa'. Please run: pip install c2pa")
    raise

# --- Setup ---
logger = logging.getLogger(__name__)
console = Console()

# -----------------------------------------------------------------
#
# A. CLI Command Definitions
#
# -----------------------------------------------------------------

# This is the Typer app that the plugin will import
cli_app = typer.Typer(
    name="media-adv",
    help="Advanced media analysis (forensics, deepfake, C2PA, AI gen)."
)

@cli_app.command(name="analyze", help="Run all advanced media analyses on a file.")
def run_full_analysis(
    file_path: Annotated[str, typer.Argument(help="The path to the media file to analyze.")]
):
    """
    Runs the full suite of analyses: forensics, deepfake, provenance, and AI trace.
    """
    logger.info(f"Running full advanced media analysis on: {file_path}")
    try:
        result = analyze_advanced_media(file_path)
        console.print(JSON.from_data(result))
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
    except Exception as e:
        logger.error(f"An error occurred during full analysis: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli_app.command(name="forensics", help="Perform forensic artifact scan (ELA, PRNU, clone detect).")
def run_forensics(
    file_path: Annotated[str, typer.Argument(help="The path to the image file.")]
):
    """Runs only the forensic artifact scan."""
    logger.info(f"Running forensics on: {file_path}")
    try:
        scanner = ForensicArtifactScan(file_path)
        result = scanner.analyze()
        console.print(JSON.from_data(result))
    except Exception as e:
        logger.error(f"Forensics scan failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli_app.command(name="deepfake", help="Run heuristic-based deepfake detection (visual, audio).")
def run_deepfake_check(
    file_path: Annotated[str, typer.Argument(help="The path to the media file.")]
):
    """Runs only the deepfake detection."""
    logger.info(f"Running deepfake check on: {file_path}")
    try:
        detector = DeepfakeMultimodal(file_path)
        result = detector.analyze()
        console.print(JSON.from_data(result))
    except Exception as e:
        logger.error(f"Deepfake check failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli_app.command(name="provenance", help="Check for C2PA / Content Credentials.")
def run_provenance_check(
    file_path: Annotated[str, typer.Argument(help="The path to the media file.")]
):
    """Runs only the content provenance check."""
    logger.info(f"Running provenance check on: {file_path}")
    try:
        checker = ContentProvenanceCheck(file_path)
        result = checker.check_provenance()
        console.print(JSON.from_data(result))
    except Exception as e:
        logger.error(f"Provenance check failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli_app.command(name="ai-trace", help="Trace media origin to a GenAI model via metadata.")
def run_ai_trace(
    file_path: Annotated[str, typer.Argument(help="The path to the media file.")]
):
    """Runs only the AI generation tracer."""
    logger.info(f"Running AI trace on: {file_path}")
    try:
        tracer = AiGenerationTracer(file_path)
        result = tracer.trace_generation()
        console.print(JSON.from_data(result))
    except Exception as e:
        logger.error(f"AI trace failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")


# --- NEW CLI COMMAND ADDED ---
@cli_app.command(name="synthetic-media-audit", help="Run specialized audit for AI-gen origin.")
def run_synthetic_media_audit(
    file_path: Annotated[str, typer.Argument(help="The path to the media file.")]
):
    """Runs specialized audit to categorize and score AI-generation origin."""
    logger.info(f"Running synthetic media audit on: {file_path}")
    try:
        auditor = SyntheticMediaAudit(file_path)
        result = auditor.analyze()
        # Convert Pydantic model to dict for JSON output
        console.print(JSON.from_data(result.model_dump(exclude_none=True)))
    except Exception as e:
        logger.error(f"Synthetic media audit failed: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")


# -----------------------------------------------------------------
#
# B. Core Analysis Logic
#
# -----------------------------------------------------------------




# --- Helper Utilities ---

def _load_image(file_path: Path) -> Tuple[Optional[np.ndarray], Optional[Image.Image]]:
    try:
        cv2_image = cv2.imread(str(file_path))
        if cv2_image is None: raise IOError("CV2 failed to load image.")
        cv2_image_rgb = cv2.cvtColor(cv2_image, cv2.COLOR_BGR2RGB)
        pil_image = Image.fromarray(cv2_image_rgb)
        return cv2_image, pil_image
    except Exception as e:
        logger.error(f"Failed to load image {file_path}: {e}")
        return None, None

def _check_ffprobe() -> bool:
    try:
        subprocess.run(['ffprobe', '-version'], capture_output=True, check=True, errors='ignore')
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("ffprobe (from ffmpeg) is not found in system PATH. Codec/Audio analysis will be skipped.")
        return False

HAS_FFPROBE = _check_ffprobe()

def _calculate_blur(image: np.ndarray) -> float:
    if image.ndim == 3:
        image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    return cv2.Laplacian(image, cv2.CV_64F).var()

# --- Module 1: Forensic Artifact Scan ---

class ForensicArtifactScan:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        self.cv2_image, self.pil_image = _load_image(self.file_path)
        if self.cv2_image is None or self.pil_image is None:
            raise IOError(f"Failed to load image for forensic analysis: {self.file_path}")
        
        try:
            self.sift = cv2.SIFT_create()
        except AttributeError:
            try:
                self.sift = cv2.xfeatures2d.SIFT_create()
            except AttributeError:
                logger.error("SIFT not available. Install 'opencv-contrib-python-headless'.")
                self.sift = None

    def analyze(self) -> Dict[str, Any]:
        return {
            "ela_result": self._run_ela(),
            "prnu_match": self._run_prnu_match(),
            "clone_detection": self._run_clone_detection(),
        }

    def _run_ela(self) -> Dict[str, Any]:
        try:
            buffer = io.BytesIO()
            self.pil_image.save(buffer, format='JPEG', quality=95)
            buffer.seek(0)
            resaved_pil = Image.open(buffer)
            ela_image = ImageChops.difference(self.pil_image, resaved_pil)
            ela_np = np.array(ela_image)
            mean_diff = float(np.mean(ela_np))
            is_suspicious = bool(mean_diff > 3.0) 
            return {
                "status": "completed",
                "mean_ela_value": round(mean_diff, 4),
                "max_ela_value": float(np.max(ela_np)),
                "is_suspicious": is_suspicious,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _run_prnu_match(self) -> Dict[str, Any]:
        try:
            image_gray = img_as_float(skio.imread(self.file_path, as_gray=True))
            sigma_est = estimate_sigma(image_gray, average_sigmas=True)
            denoised_image = denoise_wavelet(image_gray, sigma=sigma_est, multichannel=False)
            noise_residual = image_gray - denoised_image
            return {
                "status": "completed",
                "noise_residual_variance": float(np.var(noise_residual)),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _run_clone_detection(self) -> Dict[str, Any]:
        if not self.sift:
            return {"status": "error", "message": "SIFT detector not available."}
        try:
            gray_image = cv2.cvtColor(self.cv2_image, cv2.COLOR_BGR2GRAY)
            keypoints, descriptors = self.sift.detectAndCompute(gray_image, None)
            if descriptors is None or len(descriptors) < 2:
                return {"status": "completed", "cloned_keypoints_found": 0, "is_suspicious": False}

            bf = cv2.BFMatcher()
            matches = bf.knnMatch(descriptors, descriptors, k=2)
            good_matches = [m for m, n in matches if m.queryIdx != m.trainIdx and m.distance < 0.75 * n.distance]
            num_cloned_keypoints = len(good_matches)
            return {
                "status": "completed",
                "cloned_keypoints_found": num_cloned_keypoints,
                "is_suspicious": num_cloned_keypoints > 20,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

# --- Module 2: Deepfake Multimodal ---

class DeepfakeMultimodal:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        cascade_path = os.path.join(cv2.data.haarcascades, 'haarcascade_frontalface_default.xml')
        if not os.path.exists(cascade_path):
             raise FileNotFoundError(f"Could not find Haar Cascade file: {cascade_path}")
        self.face_cascade = cv2.CascadeClassifier(cascade_path)

    def analyze(self) -> Dict[str, Any]:
        visual_results = self._analyze_visual()
        audio_results = self._analyze_audio()
        codec_results = self._analyze_codec()
        
        visual_score = visual_results.get("deepfake_score", 0.0)
        audio_score = audio_results.get("deepfake_score", 0.0)
        
        if visual_score > 0 and audio_score > 0:
            overall_score = (visual_score * 0.6) + (audio_score * 0.4)
        else:
            overall_score = max(visual_score, audio_score)
        
        return {
            "visual_analysis": visual_results,
            "audio_analysis": audio_results,
            "codec_analysis": codec_results,
            "overall_deepfake_score": round(overall_score, 4),
            "status": "completed_heuristic_analysis"
        }

    def _analyze_visual(self) -> Dict[str, Any]:
        is_video = self.file_path.suffix.lower() in [".mp4", ".mov", ".avi", ".mkv"]
        is_image = self.file_path.suffix.lower() in [".jpg", ".jpeg", ".png"]
        if not is_video and not is_image:
            return {"status": "skipped", "details": "Not a visual file.", "deepfake_score": 0.0}

        face_locations = []
        blur_inconsistencies = []
        try:
            if is_video:
                cap = cv2.VideoCapture(str(self.file_path))
                frame_count = 0
                while cap.isOpened() and frame_count < 50:
                    ret, frame = cap.read()
                    if not ret: break
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
                    if len(faces) > 0:
                        (x, y, w, h) = faces[0]
                        face_locations.append((x + w // 2, y + h // 2))
                        face_blur = _calculate_blur(frame[y:y+h, x:x+w])
                        frame_blur = _calculate_blur(frame)
                        if frame_blur > 100 and abs(face_blur - frame_blur) > (frame_blur * 0.5):
                            blur_inconsistencies.append(abs(face_blur - frame_blur))
                    frame_count += 1
                cap.release()
            elif is_image:
                frame = cv2.imread(str(self.file_path))
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
                if len(faces) > 0:
                    (x, y, w, h) = faces[0]
                    face_blur = _calculate_blur(frame[y:y+h, x:x+w])
                    frame_blur = _calculate_blur(frame)
                    if frame_blur > 100 and abs(face_blur - frame_blur) > (frame_blur * 0.5):
                        blur_inconsistencies.append(abs(face_blur - frame_blur))
            
            score = 0.0
            artifacts = []
            if len(face_locations) > 10:
                distances = [math.dist(face_locations[i-1], face_locations[i]) for i in range(1, len(face_locations))]
                mean_dist, std_dist = np.mean(distances), np.std(distances)
                if std_dist > (mean_dist * 2) and std_dist > 10:
                    artifacts.append(f"temporal_jitter_detected (std_dev: {std_dist:.2f})")
                    score = max(score, 0.6)
            if len(blur_inconsistencies) > 0:
                artifacts.append(f"blur_inconsistency_detected (count: {len(blur_inconsistencies)})")
                score = max(score, 0.75)

            return {"status": "completed", "artifacts_found": artifacts, "deepfake_score": score}
        except Exception as e:
            return {"status": "error", "message": str(e), "deepfake_score": 0.0}

    def _analyze_audio(self) -> Dict[str, Any]:
        try:
            if not HAS_FFPROBE:
                return {"status": "skipped", "details": "ffprobe not found."}
            check_cmd = ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_streams', '-select_streams', 'a', str(self.file_path)]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            if not result.stdout or not json.loads(result.stdout).get('streams'):
                return {"status": "skipped", "details": "No audio stream found.", "deepfake_score": 0.0}
            y, sr = librosa.load(self.file_path, sr=None)
        except Exception as e:
             return {"status": "skipped", "details": f"Audio load failed: {e}", "deepfake_score": 0.0}

        try:
            pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
            voiced_pitches = pitches[magnitudes > np.median(magnitudes)]
            voiced_pitches = voiced_pitches[voiced_pitches > 0]
            if len(voiced_pitches) < 100:
                return {"status": "completed", "details": "Not enough voiced audio.", "deepfake_score": 0.0}

            pitch_std_dev = float(np.std(voiced_pitches))
            score = 0.0
            artifacts = []
            if pitch_std_dev < 15: # Heuristic for unnatural stability
                artifacts.append(f"unnaturally_stable_pitch (std_dev: {pitch_std_dev:.2f})")
                score = (15.0 - pitch_std_dev) / 15.0
            
            return {
                "status": "completed",
                "pitch_std_dev_hz": round(pitch_std_dev, 4),
                "artifacts_found": artifacts,
                "deepfake_score": round(score, 4),
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "deepfake_score": 0.0}

    def _analyze_codec(self) -> Dict[str, Any]:
        if not HAS_FFPROBE: return {"status": "skipped", "details": "ffprobe not found."}
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', str(self.file_path)],
                capture_output=True, text=True, check=True
            )
            codec_data = json.loads(result.stdout)
            suspicious_tags = []
            if 'format' in codec_data and 'tags' in codec_data['format']:
                tags = codec_data['format']['tags']
                for key, value in tags.items():
                    val_lower = str(value).lower()
                    if "gan" in val_lower or "synthetic" in val_lower or "deepfake" in val_lower:
                        suspicious_tags.append({key: value})
            return {
                "status": "completed",
                "suspicious_metadata_tags": suspicious_tags
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

# --- Module 3: Content Provenance ---

class ContentProvenanceCheck:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

    def check_provenance(self) -> Dict[str, Any]:
        try:
            manifest_store_json = c2pa.read_file(str(self.file_path), 'application/json')
            if not manifest_store_json:
                return {"status": "not_found", "valid": False}
            return {
                "status": "found",
                "valid_signature": True, # Placeholder until SDK provides simple validation
                "manifest_store": json.loads(manifest_store_json)
            }
        except C2paError as e:
            return {"status": "error", "message": f"C2PA SDK error: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

# --- Module 4: AI Generation Tracer ---

class AiGenerationTracer:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

    def trace_generation(self) -> Dict[str, Any]:
        exif_clues = self._check_exif()
        is_ai = bool(exif_clues["model_found"])
        return {
            "is_ai_generated": is_ai,
            "confidence_score": 1.0 if is_ai else 0.0,
            "suspected_model": exif_clues["model_found"] or "Unknown",
            "evidence": [exif_clues["evidence"]] if is_ai else []
        }

    def _check_exif(self) -> Dict[str, Any]:
        try:
            img = Image.open(self.file_path)
            all_text = ""
            if exif_data := img.getexif():
                all_text += exif_data.get(305, "") + " " # Software
                all_text += exif_data.get(315, "") + " " # Artist
                all_text += exif_data.get(270, "") + " " # ImageDescription
            for key, value in img.info.items():
                if isinstance(value, str): all_text += value + " "
            all_text = all_text.lower()
            
            models = {
                "DALL-E": "dall-e",
                "Midjourney": "midjourney",
                "Stable Diffusion": "stable diffusion",
                "Stable Diffusion (ComfyUI)": "created with comfyui"
            }
            for model_name, keyword in models.items():
                if keyword in all_text:
                    return {"model_found": model_name, "evidence": f"'{keyword}' string in metadata"}
            return {"model_found": None, "evidence": None}
        except Exception as e:
            return {"model_found": None, "error": f"Could not read EXIF: {e}"}


# --- NEW MODULE CLASS ADDED ---
# --- Module 5: Synthetic Media Audit ---

class SyntheticMediaAudit:
    """
    A meta-analyzer that combines results from other modules to create
    a single, scored audit for synthetic media.
    """
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        self.file_str = str(self.file_path)
        
        self.media_type = "Unknown"
        suffix = self.file_path.suffix.lower()
        if suffix in [".jpg", ".jpeg", ".png", ".bmp", ".tiff"]:
            self.media_type = "Image"
        elif suffix in [".mp4", ".mov", ".avi", ".mkv", ".wav", ".mp3"]:
            self.media_type = "Audio/Video"

    def analyze(self) -> SyntheticMediaAuditResult:
        """
        Runs a specialized audit to categorize and score synthetic media.
        This function aggregates findings from other tools.
        """
        details: Dict[str, Any] = {}
        confidence_scores: List[float] = []
        model_found = "Unknown"

        try:
            # 1. Run AI Generation Tracer (Metadata check)
            if self.media_type == "Image":
                trace_result = AiGenerationTracer(self.file_str).trace_generation()
                details["ai_trace"] = trace_result
                if trace_result.get("is_ai_generated"):
                    confidence_scores.append(trace_result.get("confidence_score", 1.0))
                    model_found = trace_result.get("suspected_model", "Unknown")

            # 2. Run Deepfake/Synthetic Heuristics
            deepfake_result = DeepfakeMultimodal(self.file_str).analyze()
            details["deepfake_heuristics"] = deepfake_result
            df_score = deepfake_result.get("overall_deepfake_score", 0.0)
            if df_score > 0.5:
                confidence_scores.append(df_score)
                if model_found == "Unknown":
                    model_found = "Suspected Deepfake (GAN/Heuristic)"

            # 3. Run Forensic Artifact Scan
            if self.media_type == "Image":
                forensic_result = ForensicArtifactScan(self.file_str).analyze()
                details["forensic_artifacts"] = forensic_result
                if forensic_result.get("ela_result", {}).get("is_suspicious"):
                    confidence_scores.append(0.4) # ELA is a weak indicator
                if forensic_result.get("clone_detection", {}).get("is_suspicious"):
                    confidence_scores.append(0.6) # Clone detect is a moderate indicator
            
            # 4. Check C2PA for "created by" AI
            provenance_result = ContentProvenanceCheck(self.file_str).check_provenance()
            details["content_provenance"] = provenance_result
            if provenance_result.get("status") == "found":
                manifest = provenance_result.get("manifest_store", {})
                # This is a simplified check. A real one would parse the manifest tree.
                manifest_str = json.dumps(manifest).lower()
                if '"action": "c2pa.created"' in manifest_str and '"softwareagent":' in manifest_str:
                     if "adobe" in manifest_str or "photoshop" in manifest_str:
                        confidence_scores.append(0.9)
                        if "generative" in manifest_str:
                             model_found = "Adobe Firefly (C2PA)"
                             confidence_scores.append(1.0)


            # Final scoring
            final_confidence = max(confidence_scores) if confidence_scores else 0.0
            
            return SyntheticMediaAuditResult(
                file_path=self.file_str,
                media_type=self.media_type,
                is_synthetic=final_confidence > 0.5,
                confidence=round(final_confidence, 4),
                suspected_origin_model=model_found,
                analysis_details=details
            )

        except Exception as e:
            logger.error(f"Synthetic media audit failed: {e}", exc_info=True)
            return SyntheticMediaAuditResult(
                file_path=self.file_str,
                media_type=self.media_type,
                confidence=0.0,
                error=str(e)
            )


# --- Main Wrapper Function ---

def analyze_advanced_media(file_path: str) -> Dict[str, Any]:
    logger.info(f"--- Starting Advanced Media Analysis for {file_path} ---")
    file_results = {}
    p = Path(file_path)

    try:
        if p.suffix.lower() in [".jpg", ".jpeg", ".png", ".bmp", ".tiff"]:
            file_results["forensic_artifacts"] = ForensicArtifactScan(file_path).analyze()
        else:
            file_results["forensic_artifacts"] = {"status": "skipped"}
    except Exception as e:
        file_results["forensic_artifacts"] = {"error": str(e)}

    try:
        file_results["deepfake_multimodal"] = DeepfakeMultimodal(file_path).analyze()
    except Exception as e:
        file_results["deepfake_multimodal"] = {"error": str(e)}

    try:
        file_results["content_provenance"] = ContentProvenanceCheck(file_path).check_provenance()
    except Exception as e:
        file_results["content_provenance"] = {"error": str(e)}

    try:
        if p.suffix.lower() in [".jpg", ".jpeg", ".png"]:
            file_results["ai_generation_trace"] = AiGenerationTracer(file_path).trace_generation()
        else:
            file_results["ai_generation_trace"] = {"status": "skipped"}
    except Exception as e:
        file_results["ai_generation_trace"] = {"error": str(e)}

    # --- ADDED NEW MODULE TO WRAPPER ---
    try:
        file_results["synthetic_media_audit"] = SyntheticMediaAudit(file_path).analyze().model_dump(exclude_none=True)
    except Exception as e:
        file_results["synthetic_media_audit"] = {"error": str(e)}
    # --- END ADDITION ---

    logger.info(f"--- Completed Advanced Media Analysis for {file_path} ---")
    return file_results

@cli_app.command(name="encode-covert", help="Hide a secret message in an image (LSB).")
def run_encode_covert(
    input_image: Annotated[str, typer.Argument(help="Path to the original image (PNG).")],
    message: Annotated[str, typer.Option(..., "--message", "-m", help="The secret message to hide.")],
    output_image: Annotated[str, typer.Option(..., "--output", "-o", help="Path to save the new image.")],
):
    """
    (NEW) Encodes a secret message into an image using LSB steganography.
    """
    try:
        new_img = encode_message_in_image(input_image, message)
        new_img.save(output_image)
        console.print(f"[green]Message successfully hidden in {output_image}[/green]")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Input file not found: {input_image}")
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {e}")

@cli_app.command(name="decode-covert", help="Extract a secret message from an image (LSB).")
def run_decode_covert(
    input_image: Annotated[str, typer.Argument(help="Path to the image to scan.")],
):
    """
    (NEW) Decodes a secret message from an image.
    """
    try:
        message = decode_message_from_image(input_image)
        if message:
            console.print(f"[bold green]Message Found:[/bold green]\n{message}")
        else:
            console.print("[yellow]No hidden message found (or end-of-message token missing).[/yellow]")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Input file not found: {input_image}")
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {e}")


# -----------------------------------------------------------------
#
# B. Core Analysis Logic
#
# -----------------------------------------------------------------

# --- NEW COVERT COMMS (STEGANOGRAPHY) FUNCTIONS ---

def _str_to_bin(message: str) -> str:
    """Converts a UTF-8 string to its binary representation."""
    return ''.join(format(byte, '08b') for byte in message.encode('utf-8'))

def _bin_to_str(binary: str) -> str:
    """Converts a binary string back to a UTF-8 string."""
    try:
        byte_chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]
        bytes_list = [int(chunk, 2) for chunk in byte_chunks if len(chunk) == 8]
        return bytearray(bytes_list).decode('utf-8')
    except Exception as e:
        logger.warning(f"Failed to decode binary string: {e}")
        return "" # Return empty string on decode error

def encode_message_in_image(image_path: str, message: str) -> Image.Image:
    """
    Hides a secret message in an image using LSB steganography.
    """
    try:
        img = Image.open(image_path).convert('RGB')
    except FileNotFoundError:
        raise
    
    # Add a delimiter to know when the message ends
    message += "::END::"
    message_bin = _str_to_bin(message)
    message_len = len(message_bin)
    
    img_data = img.getdata()
    total_pixels = len(img_data)
    
    # Need 3 pixels per bit (R, G, B channels)
    if message_len > total_pixels * 3:
        raise ValueError(f"Message is too long for this image. Max bits: {total_pixels * 3}")
        
    new_data = []
    data_index = 0
    
    for pixel in img_data:
        if data_index < message_len:
            # Modify the pixel
            new_pix = []
            for i in range(3): # R, G, B
                if data_index < message_len:
                    # Modify the LSB
                    new_val = (pixel[i] & 0xFE) | int(message_bin[data_index])
                    new_pix.append(new_val)
                    data_index += 1
                else:
                    new_pix.append(pixel[i])
            new_data.append(tuple(new_pix))
        else:
            # No more message, just append the original pixel
            new_data.append(pixel)
            
    new_img = Image.new('RGB', img.size)
    new_img.putdata(new_data)
    return new_img

def decode_message_from_image(image_path: str) -> Optional[str]:
    """
    Extracts a secret LSB-encoded message from an image.
    """
    try:
        img = Image.open(image_path).convert('RGB')
    except FileNotFoundError:
        raise
        
    img_data = img.getdata()
    binary_message = ""
    delimiter = "::END::"
    delimiter_bin = _str_to_bin(delimiter)

    for pixel in img_data:
        for val in pixel[:3]: # R, G, B
            binary_message += str(val & 1) # Extract LSB
            
            # Check if the end of the binary message matches the delimiter
            if binary_message.endswith(delimiter_bin):
                # Found the end
                message_bin_only = binary_message[:-len(delimiter_bin)]
                return _bin_to_str(message_bin_only)
    
    # If we get here, we never found the delimiter
    return None