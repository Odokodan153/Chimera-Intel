import pytest
from unittest.mock import AsyncMock, patch
from typer.testing import CliRunner
import json
from src.chimera_intel.core.chemint import (
    chemint_app,
    get_chemical_properties,
    search_chemical_patents,
    analyze_safety_data_sheet,
)
from src.chimera_intel.core.schemas import CHEMINTResult, ChemInfo, PatentInfo, SDSData

# Standard Pytest CLI runner setup

runner = CliRunner()

# --- Mock Data ---

# Mock for get_chemical_properties

MOCK_PUBCHEM_SUCCESS = {
    "PropertyTable": {
        "Properties": [
            {
                "CID": 240,
                "MolecularWeight": 30.03,
                "IUPACName": "formic acid;hydride",
                "CanonicalSMILES": "C=O",
            }
        ]
    }
}
MOCK_PUBCHEM_NO_DATA = {"PropertyTable": {"Properties": []}}

# Mock for search_chemical_patents

MOCK_PATENT_SUCCESS = [
    PatentInfo(
        patent_id="EP3048777B1",
        title="Method for synthesizing a high-temperature resistant polymer",
        applicant="Material Dynamics AG",
        publication_date="2023-11-15",
        summary="A novel polymerization technique...",
        country="EP",
    )
]

# Mock for analyze_safety_data_sheet

MOCK_SDS_SUCCESS = [
    SDSData(
        cas_number="67-64-1",
        autoignition_temp_C=465.0,
        flash_point_C=-20.0,
        nfpa_fire_rating=3,
        toxicology_summary="Low acute toxicity, primarily irritant via inhalation. Highly flammable liquid.",
    )
]

# --- Test Suite 1: get_chemical_properties (Existing tests) ---


@pytest.mark.asyncio
async def test_get_chemical_properties_success():
    """Tests successful retrieval and parsing of PubChem data."""
    with patch("src.chimera_intel.core.chemint.async_client") as mock_client:
        mock_response = AsyncMock(status_code=200)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = MOCK_PUBCHEM_SUCCESS
        mock_client.get.return_value = mock_response

        result = await get_chemical_properties(cid=240)

        assert isinstance(result, CHEMINTResult)
        assert result.total_results == 1
        assert result.results[0].cid == 240


@patch("src.chimera_intel.core.chemint.get_chemical_properties")
def test_chemint_cli_lookup_success(mock_get_chemical_properties, tmp_path):
    """Tests the 'chemint lookup' CLI command with successful data."""
    mock_result = CHEMINTResult(
        total_results=1,
        results=[
            ChemInfo(
                cid=240,
                molecular_weight=30.03,
                iupac_name="Formaldehyde",
                canonical_smiles="C=O",
            )
        ],
    )
    mock_get_chemical_properties.return_value = mock_result
    output_file = tmp_path / "chem_results.json"

    result = runner.invoke(
        chemint_app, ["lookup", "--cid", "240", "-o", str(output_file)]
    )

    assert result.exit_code == 0
    assert "Chemical Found (CID: 240)" in result.output

    with open(output_file, "r") as f:
        data = json.load(f)
        assert data["total_results"] == 1


# --- Test Suite 2: search_chemical_patents (New tests) ---


@pytest.mark.asyncio
async def test_search_chemical_patents_success():
    """Tests successful retrieval of patent data (simulated)."""
    with patch("src.chimera_intel.core.chemint.async_client"), patch(
        "src.chimera_intel.core.chemint.asyncio.sleep", return_value=None
    ):

        keyword = "high-temp polymer"
        result = await search_chemical_patents(keyword)

        assert isinstance(result, CHEMINTResult)
        assert result.total_results == 1
        assert result.results[0].patent_id == "EP3048777B1"
        assert result.results[0].applicant == "Material Dynamics AG"


@patch("src.chimera_intel.core.chemint.search_chemical_patents")
def test_chemint_cli_patent_search_success(mock_search_chemical_patents, tmp_path):
    """Tests the 'chemint patent-search' CLI command."""
    mock_result = CHEMINTResult(total_results=1, results=MOCK_PATENT_SUCCESS)
    mock_search_chemical_patents.return_value = mock_result
    keyword = "polymer"
    output_file = tmp_path / "patent_results.json"

    result = runner.invoke(
        chemint_app, ["patent-search", "--keyword", keyword, "-o", str(output_file)]
    )

    assert result.exit_code == 0
    assert "Patent & Research Intelligence" in result.output
    assert "Material Dynamics AG" in result.output

    with open(output_file, "r") as f:
        data = json.load(f)
        assert data["total_results"] == 1


# --- Test Suite 3: analyze_safety_data_sheet (New tests) ---


@pytest.mark.asyncio
async def test_analyze_sds_data_success():
    """Tests successful retrieval of SDS-like data (simulated)."""
    with patch("src.chimera_intel.core.chemint.async_client"), patch(
        "src.chimera_intel.core.chemint.asyncio.sleep", return_value=None
    ):

        cas = "67-64-1"
        result = await analyze_safety_data_sheet(cas)

        assert isinstance(result, CHEMINTResult)
        assert result.total_results == 1
        assert result.results[0].cas_number == cas
        assert result.results[0].flash_point_C == -20.0
        assert result.results[0].nfpa_fire_rating == 3


@patch("src.chimera_intel.core.chemint.analyze_safety_data_sheet")
def test_chemint_cli_sds_analysis_success(mock_analyze_safety_data_sheet, tmp_path):
    """Tests the 'chemint sds-analysis' CLI command."""
    mock_result = CHEMINTResult(total_results=1, results=MOCK_SDS_SUCCESS)
    mock_analyze_safety_data_sheet.return_value = mock_result
    cas = "67-64-1"
    output_file = tmp_path / "sds_results.json"

    result = runner.invoke(
        chemint_app, ["sds-analysis", "--cas", cas, "-o", str(output_file)]
    )

    assert result.exit_code == 0
    assert "Hazard Profile for CAS: 67-64-1" in result.output
    assert "Flash Point" in result.output

    with open(output_file, "r") as f:
        data = json.load(f)
        assert data["total_results"] == 1
