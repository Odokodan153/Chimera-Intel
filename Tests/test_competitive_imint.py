"""
Tests for the Competitive Image Intelligence (COMPINT) module.

These tests mock the underlying analysis functions to test the CLI
and the orchestration logic, ensuring the correct schemas are used.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, ANY

# Import the CLI app to be tested
from chimera_intel.core.competitive_imint import compint_app

# Import schemas needed for mock return values
from chimera_intel.core.schemas import (
    SimilarityAttributionResult,
    ElaResult,
    PrnuMatch,
    CloneDetection,
    AiGenerationTraceResult,
    DeepfakeAnalysisResult,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_file(tmp_path):
    """Create a dummy file for 'exists=True' checks."""
    f = tmp_path / "fake_image.jpg"
    f.write_text("dummy image content")
    return str(f)


# --- Mock all external dependencies ---


@patch("chimera_intel.core.competitive_imint.analyze_image_content")
def test_cli_analyze_product(mock_analyze, runner, mock_file):
    """Tests the 'analyze' command for 'product' use case."""
    mock_analyze.return_value = "AI analysis of the product."

    result = runner.invoke(
        compint_app, ["analyze", mock_file, "--use-case", "product"]
    )

    assert result.exit_code == 0
    # Check that the correct prompt from the dictionary was used
    mock_analyze.assert_called_once_with(mock_file, ANY)
    assert "Identify all products" in mock_analyze.call_args[0][1]
    assert "AI analysis of the product." in result.stdout


@patch("chimera_intel.core.competitive_imint.compute_hashes_and_embeddings")
@patch("chimera_intel.core.competitive_imint.reverse_image_search")
@patch("chimera_intel.core.competitive_imint.check_similarity_and_log_asset")
@patch("chimera_intel.core.competitive_imint.Image.open")
def test_cli_attribution(
    mock_img_open,
    mock_check_internal,
    mock_reverse_search,
    mock_compute_hashes,
    runner,
    mock_file,
):
    """Tests the 'attribution' command."""
    mock_img_open.return_value = MagicMock()
    mock_compute_hashes.return_value = ("sha256", "phash123", [0.1, 0.2])
    mock_reverse_search.return_value = ["http://example.com/match.jpg"]
    
    # Mock the Pydantic model return value
    mock_check_internal.return_value = SimilarityAttributionResult(
        is_reused_asset=True, 
        similar_assets_found=[{"id": "internal_001", "distance": 0.1, "metadata": {}}]
    )

    result = runner.invoke(compint_app, ["attribution", mock_file])

    assert result.exit_code == 0
    mock_compute_hashes.assert_called_once()
    mock_reverse_search.assert_called_once_with("phash123")
    mock_check_internal.assert_called_once_with([0.1, 0.2], "phash123", mock_file)
    assert "http://example.com/match.jpg" in result.stdout
    assert "internal_001" in result.stdout


@patch("chimera_intel.core.competitive_imint.analyze_image_content")
@patch("chimera_intel.core.competitive_imint.ForensicArtifactScan.analyze")
def test_cli_brand_audit(mock_forensic_scan, mock_analyze, runner, mock_file):
    """Tests the 'brand-audit' command."""
    mock_analyze.return_value = "Potential Misuse/Counterfeit"
    
    # Mock the dictionary return value from the .analyze() method
    mock_forensic_scan.return_value = {
        "ela_result": {"status": "completed", "is_suspicious": True, "mean_ela_value": 10.5},
        "prnu_match": {"status": "completed", "noise_residual_variance": 0.5},
        "clone_detection": {"status": "completed", "cloned_keypoints_found": 50, "is_suspicious": True},
    }

    result = runner.invoke(compint_app, ["brand-audit", mock_file])

    assert result.exit_code == 0
    # Check that the specific counterfeit prompt was used
    mock_analyze.assert_called_once_with(mock_file, ANY)
    assert "brand misuse or counterfeit" in mock_analyze.call_args[0][1]
    
    mock_forensic_scan.assert_called_once()
    assert "Potential Misuse/Counterfeit" in result.stdout
    # Check that the forensics model was correctly parsed
    assert '"is_suspicious": true' in result.stdout
    assert '"cloned_keypoints_found": 50' in result.stdout


@patch("chimera_intel.core.competitive_imint.DeepfakeMultimodal.analyze")
@patch("chimera_intel.core.competitive_imint.AiGenerationTracer.trace_generation")
def test_cli_counter_disinfo(mock_ai_trace, mock_deepfake, runner, mock_file):
    """Tests the 'counter-disinfo' command."""
    # Mock the dictionary returns from the .analyze() methods
    mock_deepfake.return_value = {"overall_deepfake_score": 0.9, "status": "completed_heuristic_analysis"}
    mock_ai_trace.return_value = {
        "is_ai_generated": True,
        "confidence_score": 1.0,
        "suspected_model": "DALL-E",
        "evidence": ["'dall-e' string in metadata"],
        "error": None
    }

    result = runner.invoke(compint_app, ["counter-disinfo", mock_file])

    assert result.exit_code == 0
    mock_deepfake.assert_called_once()
    mock_ai_trace.assert_called_once()
    assert '"overall_deepfake_score": 0.9' in result.stdout
    assert '"suspected_model": "DALL-E"' in result.stdout


@patch("chimera_intel.core.competitive_imint.pathlib.Path.read_bytes")
@patch("chimera_intel.core.competitive_imint.store_evidence")
def test_cli_secure_evidence(mock_store_evidence, mock_read_bytes, runner, mock_file):
    """Tests the 'secure-evidence' command."""
    mock_read_bytes.return_value = b"dummy image content"
    mock_store_evidence.return_value = "receipt-id-12345"

    result = runner.invoke(
        compint_app, ["secure-evidence", mock_file, "--project", "legal_case_001"]
    )

    assert result.exit_code == 0
    mock_read_bytes.assert_called_once()
    mock_store_evidence.assert_called_once_with(
        content=b"dummy image content",
        source=f"file://{mock_file}",
        target="legal_case_001",
    )
    assert "Successfully encrypted and stored" in result.stdout
    assert "receipt-id-12345" in result.stdout