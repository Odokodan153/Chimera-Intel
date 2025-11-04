"""
Module for the full Image Intelligence & Forensic Detection Pipeline (Step-by-Step).

This module orchestrates multiple tools from IMINT and Media Forensics to
execute a comprehensive forensic pipeline.

Pipeline Steps:
A. Acquisition & Triage: Hashes, embeddings, reverse search.
B. Automated Triage: EXIF, ELA, OCR, Logo, Face Detection.
C. Similarity & Attribution: [IMPLEMENTED] Vector DB search for reused assets.
D. Deepfake / Manipulation Detection: [IMPLEMENTED] Image/Video/Audio checks.
E. Human Review & Forensics Report: Structured data output.
F. Counterintelligence Action: (Triggered by report)

New Dependencies:
pip install imagehash sentence-transformers chromadb-client moviepy librosa
"""

import typer
import logging
import os
import pathlib
import hashlib
import numpy as np
from typing import Optional, List, Tuple
from PIL import Image
from rich.console import Console
import imagehash
from datetime import datetime
from sentence_transformers import SentenceTransformer
import cv2

# --- Vector DB for Similarity (Step C) ---
import chromadb

# --- Audio Analysis (Step D) ---
import librosa
from moviepy.editor import VideoFileClip


# --- Reuse existing modules ---
from .imint import analyze_image_metadata, analyze_image_content
from .media_forensics import (
    forensic_artifact_scan,
    deepfake_multimodal_scan,
    content_provenance_check,
    load_models as load_forensic_models,
    face_cascade,
)
from .vidint import run_motion_detection, analyze as analyze_video
from .schemas import (
    ImageAnalysisResult,
    SimilarityAttributionResult,
    DeepfakeAnalysisResult,
    AudioAnomalyResult,
    ImageAcquisitionTriage,
    AutomatedTriageResult,
    ManipulationDetectionResult,
    ImageForensicsReport
)
from .utils import save_or_print_results
from .database import save_scan_to_db

# --- (Placeholder) Reverse Image Search Tool ---
# In a real scenario, this would use google_search tool or a TinEye API
from .google_search import search_google

logger = logging.getLogger(__name__)
console = Console()
pipeline_app = typer.Typer(
    name="image-pipeline",
    help="Run the full Image Intelligence & Forensic Detection Pipeline.",
)

# --- Load Models ---
# Load embedding model (CLIP)
try:
    embedding_model = SentenceTransformer("clip-ViT-B-32")
except Exception as e:
    logger.warning(f"Could not load CLIP embedding model: {e}")
    embedding_model = None

# Load face detection models from media_forensics
load_forensic_models()


# --- (Step C) Setup In-Memory Vector Database ---
try:
    # Using an in-memory client. For persistence, use:
    # chromadb.PersistentClient(path="/path/to/your/db")
    vector_client = chromadb.Client()
    image_collection = vector_client.get_or_create_collection(
        name="image_forensics_db"
    )
    console.print(
        "[dim]Initialized in-memory vector DB for similarity search.[/dim]"
    )
except Exception as e:
    logger.error(f"Failed to initialize ChromaDB: {e}")
    vector_client = None
    image_collection = None


def compute_hashes_and_embeddings(
    img: Image.Image,
) -> Tuple[str, str, Optional[List[float]]]:
    """Computes SHA256, pHash, and CLIP embedding."""
    # SHA256
    img_bytes = img.tobytes()
    sha256 = hashlib.sha256(img_bytes).hexdigest()

    # pHash
    phash = str(imagehash.phash(img))

    # CLIP Embedding
    embedding = None
    if embedding_model:
        embedding = embedding_model.encode(img).tolist()
    return sha256, phash, embedding


def reverse_image_search(phash: str) -> List[str]:
    """
    Step A: Performs a reverse image search by searching for the image's
    perceptual hash (pHash) to find exact or near-exact copies online.
    """
    if not phash or phash.startswith("N/A"):
        return []
    try:
        # Search for the pHash string in quotes to find exact matches
        query = f'"{phash}"'
        console.print(f"  > Performing reverse search for pHash: {query}")
        search_results = search_google(query)
        # Assuming search_google returns a list of result snippets or URLs
        return [str(hit) for hit in search_results[:5]]
    except Exception as e:
        logger.error(f"Reverse image search failed: {e}")
        return ["Reverse image search failed or was not configured."]


def run_ocr_and_logo(image_path: str) -> Tuple[str, str]:
    """Step B: Runs OCR and Logo detection using existing imint module."""
    try:
        ocr_text = analyze_image_content(image_path, "Extract all text from this image.")
    except Exception as e:
        ocr_text = f"OCR analysis failed: {e}"

    try:
        logo_text = analyze_image_content(
            image_path, "Identify the brand or logo in this image."
        )
    except Exception as e:
        logo_text = f"Logo analysis failed: {e}"

    return ocr_text, logo_text


def detect_faces(image_path: str) -> int:
    """Step B: Runs face detection using media_forensics cascade."""
    if not face_cascade:
        return 0
    try:
        img = cv2.imread(image_path)
        gray_frame = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray_frame, 1.1, 4)
        return len(faces)
    except Exception as e:
        logger.error(f"Face detection failed: {e}")
        return 0


def check_similarity_and_log_asset(
    embedding: Optional[List[float]], phash: str, file_path: str
) -> SimilarityAttributionResult:
    """
    Step C: Adds asset to vector DB and queries for similar assets.
    """
    result = SimilarityAttributionResult()
    if not image_collection or not embedding:
        result.error = "Vector DB not initialized or no embedding generated."
        return result

    try:
        # 1. Query for similar assets *before* adding the new one
        query_results = image_collection.query(
            query_embeddings=[embedding], n_results=5, include=["metadatas", "distances"]
        )

        # 2. Process query results
        similar_assets = []
        is_reused = False
        if query_results["ids"][0]:
            for i, (id, dist, meta) in enumerate(
                zip(
                    query_results["ids"][0],
                    query_results["distances"][0],
                    query_results["metadatas"][0],
                )
            ):
                # Don't match self. A distance of 0 is a perfect match.
                if dist < 1e-5:
                    continue
                # Use a threshold to define "similar"
                if dist < 0.2:  # 0.2 is a relatively close distance for CLIP
                    is_reused = True
                    similar_assets.append(
                        {"id": id, "distance": dist, "metadata": meta}
                    )
        
        result.is_reused_asset = is_reused
        result.similar_assets_found = similar_assets

        # 3. Add the new asset to the DB
        # Use a hash of the file path as a simple, unique ID
        asset_id = hashlib.md5(file_path.encode()).hexdigest()
        image_collection.add(
            embeddings=[embedding],
            metadatas=[{"file_path": file_path, "phash": phash, "added_time": str(datetime.now())}],
            ids=[asset_id],
        )
    except Exception as e:
        result.error = f"Vector DB operation failed: {e}"
        logger.error(f"Vector DB operation failed: {e}")

    return result


def analyze_audio_anomalies(video_path: str) -> AudioAnomalyResult:
    """
    Step D: Extracts audio from video and analyzes for spectral anomalies.
    """
    result = AudioAnomalyResult()
    # Create a unique temp file path
    base_name = os.path.basename(video_path)
    audio_path = f"temp_audio_{base_name}.wav"

    try:
        # 1. Extract audio using moviepy
        with VideoFileClip(video_path) as video:
            if video.audio is None:
                result.analysis_skipped = True
                return result
            # Suppress moviepy's stdout logging
            video.audio.write_audiofile(audio_path, logger=None)

        # 2. Analyze with Librosa
        y, sr = librosa.load(audio_path)
        
        # Calculate Spectral Flux (rate of change in the spectrum)
        sf = librosa.onset.onset_strength(y=y, sr=sr)
        
        if len(sf) < 1:
            return result
        
        # Detect anomalies: points where flux is > 3 standard deviations from the median
        median_flux = np.median(sf)
        std_dev_flux = np.std(sf)
        
        # Set a minimum threshold to avoid flagging silence
        threshold = max(median_flux + (3 * std_dev_flux), 0.1)
        
        anomalies_frames = np.where(sf > threshold)[0]
        
        if len(anomalies_frames) > 0:
            result.spectral_flux_anomalies_detected = len(anomalies_frames)
            # De-duplicate anomalies that are too close together (e.g., within 0.5 sec)
            anomaly_times = librosa.frames_to_time(anomalies_frames, sr=sr)
            final_timestamps = []
            if len(anomaly_times) > 0:
                last_time = -1
                for t in anomaly_times:
                    if (t - last_time) > 0.5:
                        final_timestamps.append(t)
                        last_time = t
            result.anomaly_timestamps = final_timestamps
            result.spectral_flux_anomalies_detected = len(final_timestamps)

    except Exception as e:
        result.error = f"Audio analysis failed: {e}"
        logger.error(f"Audio analysis failed for {video_path}: {e}")
    finally:
        # 3. Clean up temp audio file
        if os.path.exists(audio_path):
            os.remove(audio_path)
            
    return result


# --- Main Pipeline Executor ---


@pipeline_app.command(
    "run", help="Run the full forensic pipeline on a single image or video."
)
def run_image_forensics_pipeline(
    file_path: str = typer.Argument(..., exists=True, help="Path to the media file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to a JSON file."
    ),
):
    """
    Executes the step-by-step image/video forensics pipeline.
    """
    console.print(
        f"Starting forensics pipeline for: [bold cyan]{file_path}[/bold cyan]"
    )
    p_file = pathlib.Path(file_path)
    is_video = p_file.suffix.lower() in [".mp4", ".mov", ".avi", ".mkv"]

    try:
        img = Image.open(file_path)
    except Exception as e:
        if not is_video:
            console.print(f"[bold red]Error:[/bold red] Could not open image: {e}")
            raise typer.Exit(code=1)
        console.print("[yellow]File is a video, skipping image-only hashing.[/yellow]")
        img = None

    # --- Step A: Acquisition & Triage ---
    console.print("Running Step A: Acquisition & Triage...")
    if img and not is_video:
        sha256, phash, embedding = compute_hashes_and_embeddings(img)
        emb_shape = str(len(embedding)) if embedding else "None"
        # Run reverse search using the computed pHash
        reverse_hits = reverse_image_search(phash)
    else:
        sha256, phash, emb_shape = "N/A (Video)", "N/A (Video)", "N/A (Video)"
        embedding = None # No embedding for video file itself
        reverse_hits = []  # No pHash to search for

    provenance = content_provenance_check(p_file)

    step_a_results = ImageAcquisitionTriage(
        file_name=p_file.name,
        file_path=file_path,
        sha256=sha256,
        phash=phash,
        clip_embedding_shape=emb_shape,
        reverse_search_hits=reverse_hits,
        provenance=provenance,
    )

    # --- Step B: Automated Triage ---
    console.print("Running Step B: Automated Triage...")
    if not is_video:
        exif = analyze_image_metadata(file_path)
        ela = forensic_artifact_scan(p_file)
        ocr, logo = run_ocr_and_logo(file_path)
        faces = detect_faces(file_path)
    else:
        # Run vidint analysis for metadata
        console.print("File is video, running video metadata analysis...")
        try:
            analyze_video(
                file_path=file_path,
                extract_frames=None,
                detect_motion=False,
            )
            exif = ImageAnalysisResult(
                file_path=file_path, message="Video file, see console for metadata."
            )
        except Exception:
            exif = ImageAnalysisResult(
                file_path=file_path, error="Could not extract video metadata."
            )
        ela = None
        ocr = "N/A (Video)"
        logo = "N/A (Video)"
        faces = 0  # Deepfake scan will count faces

    step_b_results = AutomatedTriageResult(
        exif_analysis=exif,
        ela_triage=ela,
        ocr_text=ocr,
        detected_logos=logo,
        detected_face_count=faces,
    )

    # --- Step C: Similarity & Attribution ---
    console.print("Running Step C: Similarity & Attribution...")
    step_c_results = check_similarity_and_log_asset(embedding, phash, file_path)
    if step_c_results.is_reused_asset:
        console.print(
            f"[bold yellow]  > Reused asset detected![/bold yellow] Found {len(step_c_results.similar_assets_found)} similar assets in DB."
        )

    # --- Step D: Deepfake / Manipulation Detection ---
    console.print("Running Step D: Manipulation Detection...")
    audio_results = None
    if is_video:
        deepfake_results = deepfake_multimodal_scan(p_file)
        console.print("  > Running audio anomaly detection...")
        audio_results = analyze_audio_anomalies(file_path)
        if audio_results.spectral_flux_anomalies_detected > 0:
            console.print(
                f"[bold yellow]  > Audio anomalies detected![/bold yellow] Found {audio_results.spectral_flux_anomalies_detected} spectral flux spikes."
            )
    else:
        deepfake_results = DeepfakeAnalysisResult(
            file_path=file_path, message="File is a static image, not a video."
        )

    step_d_results = ManipulationDetectionResult(
        deepfake_scan=deepfake_results,
        audio_anomalies=audio_results
    )

    # --- Step E: Human Review & Forensics Report ---
    console.print("Running Step E: Generating Forensics Report...")
    report = ImageForensicsReport(
        acquisition_triage=step_a_results,
        automated_triage=step_b_results,
        similarity_attribution=step_c_results,
        manipulation_detection=step_d_results,
    )

    # --- Step F: Counterintelligence Action (Logging) ---
    console.print("Running Step F: Counterintelligence Triage...")
    is_malicious = False
    summary_flags = []
    if (
        step_d_results.deepfake_scan
        and step_d_results.deepfake_scan.is_deepfake
    ):
        is_malicious = True
        summary_flags.append("High confidence of deepfake manipulation.")
    
    if step_b_results.ela_triage and step_b_results.ela_triage.artifacts_found:
        is_malicious = True
        summary_flags.append("Potential manipulation (ELA/EXIF).")
        
    if step_c_results.is_reused_asset:
        summary_flags.append("Asset is reused across multiple sources.")
        
    if audio_results and audio_results.spectral_flux_anomalies_detected > 0:
        is_malicious = True
        summary_flags.append("Audio spectral anomalies detected.")

    if is_malicious:
        report.forensic_summary = "FLAGGED: " + " ".join(summary_flags)
        console.print(
            f"[bold red]MALICIOUS MEDIA DETECTED.[/bold red] {report.forensic_summary}"
        )
        # Ingest into AIA, notify legal, etc.
        # This is simulated by saving to the DB with a flag.
    else:
        report.forensic_summary = "Media appears clean."
        console.print("[green]Media appears clean.[/green]")

    # --- Save & Print ---
    results_dict = report.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=file_path,
        module="image_forensics_pipeline",
        data=results_dict,
    )
    console.print("[bold green]Forensic pipeline complete.[/bold green]")


if __name__ == "__main__":
    pipeline_app()