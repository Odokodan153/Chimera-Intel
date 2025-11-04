import pytest
from typer.testing import CliRunner
from PIL import Image
import numpy as np
import json
import pathlib
import os

# Import the app from the new module
from chimera_intel.core.image_forensics_pipeline import pipeline_app
from chimera_intel.core.schemas import (
    ImageAnalysisResult,
    ForensicArtifactResult,
    DeepfakeAnalysisResult,
    ProvenanceResult,
)
# Import the new result schemas
from chimera_intel.core.image_forensics_pipeline import (
    AudioAnomalyResult,
    SimilarityAttributionResult,
)

runner = CliRunner()


@pytest.fixture
def mock_image(tmp_path):
    """Create a dummy image file."""
    file_path = tmp_path / "test_image.png"
    img = Image.new("RGB", (100, 100), color="blue")
    img.save(file_path)
    return file_path


@pytest.fixture
def mock_video(tmp_path):
    """Create a dummy video file path."""
    file_path = tmp_path / "test_video.mp4"
    # Just need the file to exist for path checks
    with open(file_path, "w") as f:
        f.write("dummy video content")
    return file_path


@pytest.fixture
def mock_models(monkeypatch):
    """Mock all expensive AI models, DBs, and external calls."""

    # Mock SentenceTransformer
    def mock_encode(img):
        return np.random.rand(512)

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.embedding_model.encode",
        mock_encode,
    )

    # Mock google_search
    def mock_google_search(query):
        if "phash" in query:
            return ["http://example.com/similar_image.png"]
        return []

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.search_google",
        mock_google_search,
    )

    # Mock analyze_image_metadata (from imint)
    def mock_metadata(file_path):
        return ImageAnalysisResult(
            file_path=file_path, message="Mocked EXIF data."
        )

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.analyze_image_metadata",
        mock_metadata,
    )

    # Mock forensic_artifact_scan (from media_forensics)
    def mock_ela(file_path):
        return ForensicArtifactResult(
            file_path=str(file_path),
            artifacts_found=["Mocked ELA artifact"],
            confidence_scores={"ELA": 0.9},
        )

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.forensic_artifact_scan",
        mock_ela,
    )

    # Mock analyze_image_content (from imint)
    def mock_analyze_content(image_path, prompt):
        if "text" in prompt:
            return "Mocked OCR Text"
        if "logo" in prompt:
            return "Mocked Logo"
        return "Mocked AI"

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.analyze_image_content",
        mock_analyze_content,
    )

    # Mock face_cascade (from media_forensics)
    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.face_cascade",
        True,  # Enable the cascade
    )

    # Mock detect_faces
    def mock_detect_faces(image_path):
        return 2  # Simulate 2 faces found

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.detect_faces",
        mock_detect_faces,
    )

    # Mock deepfake_multimodal_scan (from media_forensics)
    def mock_deepfake(file_path):
        # Default for image test
        return DeepfakeAnalysisResult(
            file_path=str(file_path), message="File is a static image, not a video."
        )

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.deepfake_multimodal_scan",
        mock_deepfake,
    )

    # Mock content_provenance_check (from media_forensics)
    def mock_provenance(file_path):
        return ProvenanceResult(
            file_path=str(file_path), has_c2pa_credentials=True, is_valid=True
        )

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.content_provenance_check",
        mock_provenance,
    )

    # Mock save_scan_to_db
    def mock_save_db(target, module, data):
        print(f"Mocked save to DB for {module}")

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.save_scan_to_db",
        mock_save_db,
    )

    # --- Mock NEW Step C: ChromaDB ---
    def mock_chroma_query(*args, **kwargs):
        # Simulate finding one similar asset
        return {
            "ids": [["old_asset_id"]],
            "distances": [[0.1]],  # < 0.2 threshold, will trigger "reused asset"
            "metadatas": [[{"file_path": "old/image.png", "phash": "abc123"}]],
        }

    def mock_chroma_add(*args, **kwargs):
        # No-op
        pass

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.image_collection.query",
        mock_chroma_query,
    )
    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.image_collection.add",
        mock_chroma_add,
    )

    # --- Mock NEW Step D: Audio Analysis ---
    def mock_audio_analysis(video_path):
        # Simulate finding 3 anomalies
        return AudioAnomalyResult(
            spectral_flux_anomalies_detected=3,
            anomaly_timestamps=[1.5, 3.2, 5.1],
        )

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.analyze_audio_anomalies",
        mock_audio_analysis,
    )

    # Mock vidint.analyze for video test
    def mock_vidint_analyze(*args, **kwargs):
        print("Mocked video metadata analysis.")
        pass

    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.analyze_video",
        mock_vidint_analyze,
    )
    
    # Mock Image.open for video test
    original_image_open = Image.open
    def mock_image_open(file_path):
        if str(file_path).endswith(".mp4"):
            raise Exception("Cannot open video as image")
        return original_image_open(file_path)
    
    monkeypatch.setattr("chimera_intel.core.image_forensics_pipeline.Image.open", mock_image_open)


def test_pipeline_run_image(mock_image, mock_models):
    """Test the 'run' command on a standard IMAGE file."""
    output_path = pathlib.Path(mock_image.parent / "image_report.json")
    result = runner.invoke(
        pipeline_app, ["run", str(mock_image), "--output", str(output_path)]
    )

    assert result.exit_code == 0
    assert "Starting forensics pipeline" in result.stdout
    assert "Running Step C: Similarity & Attribution" in result.stdout
    assert "Reused asset detected!" in result.stdout  # Check new Step C
    assert "Forensic pipeline complete" in result.stdout
    assert output_path.exists()

    with open(output_path, "r") as f:
        report_data = json.load(f)

    # Step A checks
    assert "acquisition_triage" in report_data
    assert report_data["acquisition_triage"]["phash"]
    assert (
        report_data["acquisition_triage"]["reverse_search_hits"][0]
        == "http://example.com/similar_image.png"
    )

    # Step B checks
    assert "automated_triage" in report_data
    assert report_data["automated_triage"]["ocr_text"] == "Mocked OCR Text"
    assert report_data["automated_triage"]["detected_face_count"] == 2

    # Step C checks
    assert "similarity_attribution" in report_data
    assert report_data["similarity_attribution"]["is_reused_asset"] == True
    assert (
        len(report_data["similarity_attribution"]["similar_assets_found"]) == 1
    )
    assert (
        report_data["similarity_attribution"]["similar_assets_found"][0]["id"]
        == "old_asset_id"
    )

    # Step D checks
    assert "manipulation_detection" in report_data
    assert (
        report_data["manipulation_detection"]["deepfake_scan"]["message"]
        == "File is a static image, not a video."
    )
    assert report_data["manipulation_detection"]["audio_anomalies"] is None

    # Step F check (Summary)
    assert "FLAGGED" in report_data["forensic_summary"]
    assert "Reused asset" in report_data["forensic_summary"]


def test_pipeline_run_video(mock_video, mock_models, monkeypatch):
    """Test the 'run' command on a VIDEO file."""
    
    # Update mock deepfake scan to return a "FLAGGED" result
    def mock_deepfake_video(file_path):
        return DeepfakeAnalysisResult(
            file_path=str(file_path), is_deepfake=True, confidence=0.95
        )
    monkeypatch.setattr(
        "chimera_intel.core.image_forensics_pipeline.deepfake_multimodal_scan",
        mock_deepfake_video,
    )

    output_path = pathlib.Path(mock_video.parent / "video_report.json")
    result = runner.invoke(
        pipeline_app, ["run", str(mock_video), "--output", str(output_path)]
    )

    assert result.exit_code == 0
    assert "File is a video" in result.stdout
    assert "Running audio anomaly detection..." in result.stdout
    assert "Audio anomalies detected!" in result.stdout  # Check new Step D
    assert "MALICIOUS MEDIA DETECTED" in result.stdout
    assert output_path.exists()

    with open(output_path, "r") as f:
        report_data = json.load(f)

    # Step A checks
    assert report_data["acquisition_triage"]["phash"] == "N/A (Video)"
    assert report_data["acquisition_triage"]["sha256"] == "N/A (Video)"

    # Step B checks
    assert report_data["automated_triage"]["ocr_text"] == "N/A (Video)"
    assert (
        report_data["automated_triage"]["exif_analysis"]["message"]
        == "Video file, see console for metadata."
    )

    # Step C checks
    assert (
        report_data["similarity_attribution"]["error"]
        == "Vector DB not initialized or no embedding generated."
    )

    # Step D checks
    assert "manipulation_detection" in report_data
    assert report_data["manipulation_detection"]["deepfake_scan"]["is_deepfake"] == True
    assert (
        report_data["manipulation_detection"]["audio_anomalies"][
            "spectral_flux_anomalies_detected"
        ]
        == 3
    )
    assert (
        report_data["manipulation_detection"]["audio_anomalies"]["anomaly_timestamps"][0]
        == 1.5
    )

    # Step F check (Summary)
    assert "FLAGGED" in report_data["forensic_summary"]
    assert "deepfake manipulation" in report_data["forensic_summary"]
    assert "Audio spectral anomalies" in report_data["forensic_summary"]