import pytest
import json
from unittest.mock import AsyncMock, patch
from typer.testing import CliRunner

from src.chimera_intel.core.chemint import chemint_app
from src.chimera_intel.core.schemas import CHEMINTResult, ChemInfo, PatentInfo, SDSData

# ------------------
# Pytest Fixtures
# ------------------

@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

# --- Mock Data Fixtures ---

@pytest.fixture
def mock_chem_info():
    """Mock data for a successful chemical property lookup."""
    return ChemInfo(
        cid=240,
        molecular_weight=30.03,
        iupac_name="Formaldehyde",
        canonical_smiles="C=O",
    )

@pytest.fixture
def mock_patent_info():
    """Mock data for a successful patent search."""
    return PatentInfo(
        patent_id="EP3048777B1",
        title="Method for synthesizing a high-temperature resistant polymer",
        applicant="Material Dynamics AG",
        publication_date="2023-11-15",
        summary="A novel polymerization technique...",
        country="EP",
    )

@pytest.fixture
def mock_sds_data():
    """Mock data for a successful SDS analysis."""
    return SDSData(
        cas_number="67-64-1",
        autoignition_temp_C=465.0,
        flash_point_C=-20.0,
        nfpa_fire_rating=3,
        toxicology_summary="Low acute toxicity, primarily irritant via inhalation. Highly flammable liquid.",
    )

# --- Mocking Fixtures ---

@pytest.fixture
def mock_async_client(monkeypatch):
    """Mocks the async HTTP client for external API calls."""
    mock_client = AsyncMock()
    monkeypatch.setattr("src.chimera_intel.core.chemint.async_client", mock_client)
    return mock_client

# ------------------
# Test Suites
# ------------------

class TestChemicalLookup:
    """Tests for the 'lookup' command and its underlying function."""

    @pytest.mark.asyncio
    async def test_get_chemical_properties_success(self, mock_async_client):
        """Tests successful retrieval and parsing of PubChem data."""
        from src.chimera_intel.core.chemint import get_chemical_properties
        mock_response = AsyncMock(status_code=200)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "PropertyTable": {"Properties": [{"CID": 240}]}
        }
        mock_async_client.get.return_value = mock_response

        result = await get_chemical_properties(cid=240)

        assert isinstance(result, CHEMINTResult)
        assert result.total_results == 1
        assert result.results[0].cid == 240

    @patch("src.chimera_intel.core.chemint.get_chemical_properties")
    def test_cli_lookup_success(self, mock_get_properties, runner, mock_chem_info, tmp_path):
        """Tests the 'chemint lookup' CLI command with successful data."""
        mock_get_properties.return_value = CHEMINTResult(total_results=1, results=[mock_chem_info])
        output_file = tmp_path / "chem_results.json"

        result = runner.invoke(chemint_app, ["lookup", "--cid", "240", "-o", str(output_file)])

        assert result.exit_code == 0
        assert "Chemical Found (CID: 240)" in result.stdout
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["cid"] == 240

class TestPatentSearch:
    """Tests for the 'patent-search' command and its underlying function."""

    @pytest.mark.asyncio
    async def test_search_chemical_patents_success(self, mock_patent_info):
        """Tests successful retrieval of patent data (simulated)."""
        from src.chimera_intel.core.chemint import search_chemical_patents
        with patch("src.chimera_intel.core.chemint.asyncio.sleep", return_value=None):
             # This function now returns a static mock, so we can test it directly
            result = await search_chemical_patents("high-temp polymer")

            assert isinstance(result, CHEMINTResult)
            assert result.total_results > 0 # The mock returns a list
            assert result.results[0].applicant == mock_patent_info.applicant


    @patch("src.chimera_intel.core.chemint.search_chemical_patents")
    def test_cli_patent_search_success(self, mock_search_patents, runner, mock_patent_info, tmp_path):
        """Tests the 'chemint patent-search' CLI command."""
        mock_search_patents.return_value = CHEMINTResult(total_results=1, results=[mock_patent_info])
        output_file = tmp_path / "patent_results.json"

        result = runner.invoke(chemint_app, ["patent-search", "--keyword", "polymer", "-o", str(output_file)])

        assert result.exit_code == 0
        assert "Patent & Research Intelligence" in result.stdout
        assert "Material Dynamics AG" in result.stdout
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["applicant"] == "Material Dynamics AG"

class TestSdsAnalysis:
    """Tests for the 'sds-analysis' command and its underlying function."""

    @pytest.mark.asyncio
    async def test_analyze_sds_data_success(self, mock_sds_data):
        """Tests successful retrieval of SDS-like data (simulated)."""
        from src.chimera_intel.core.chemint import analyze_safety_data_sheet
        with patch("src.chimera_intel.core.chemint.asyncio.sleep", return_value=None):
            result = await analyze_safety_data_sheet("67-64-1")

            assert isinstance(result, CHEMINTResult)
            assert result.total_results > 0
            assert result.results[0].cas_number == mock_sds_data.cas_number


    @patch("src.chimera_intel.core.chemint.analyze_safety_data_sheet")
    def test_cli_sds_analysis_success(self, mock_analyze_sds, runner, mock_sds_data, tmp_path):
        """Tests the 'chemint sds-analysis' CLI command."""
        mock_analyze_sds.return_value = CHEMINTResult(total_results=1, results=[mock_sds_data])
        output_file = tmp_path / "sds_results.json"

        result = runner.invoke(chemint_app, ["sds-analysis", "--cas", "67-64-1", "-o", str(output_file)])

        assert result.exit_code == 0
        assert "Hazard Profile for CAS: 67-64-1" in result.stdout
        assert "Flash Point" in result.stdout
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["cas_number"] == "67-64-1"