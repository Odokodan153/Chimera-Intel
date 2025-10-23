import pytest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
# --- FIX: Corrected import path ---
from chimera_intel.core.chemint import chemint_app
# --- FIX: Added Table import for type checking in mock ---
from rich.table import Table


# ------------------
# Dummy Schema Classes
# ------------------
# (Note: These dummy classes are for test setup and don't need to be in the
#  final file if the real schemas are accessible, but we'll keep them
#  as they are part of the provided test file.)

class ChemInfo:
    def __init__(self, cid, molecular_weight, iupac_name, canonical_smiles):
        self.cid = cid
        self.molecular_weight = molecular_weight
        self.iupac_name = iupac_name
        self.canonical_smiles = canonical_smiles


class PatentInfo:
    def __init__(self, patent_id, title, applicant, publication_date, summary, country):
        self.patent_id = patent_id
        self.title = title
        self.applicant = applicant
        self.publication_date = publication_date
        self.summary = summary
        self.country = country


class SDSData:
    def __init__(
        self,
        cas_number,
        autoignition_temp_C,
        flash_point_C,
        nfpa_fire_rating,
        toxicology_summary,
    ):
        self.cas_number = cas_number
        self.autoignition_temp_C = autoignition_temp_C
        self.flash_point_C = flash_point_C
        self.nfpa_fire_rating = nfpa_fire_rating
        self.toxicology_summary = toxicology_summary


class CHEMINTResult:
    def __init__(self, total_results, results):
        self.total_results = total_results
        self.results = results


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


# ------------------
# Test Suites
# ------------------


class TestChemicalLookup:
    """Tests for the 'lookup' command."""

    # --- FIX: Corrected patch path ---
    @patch("chimera_intel.core.chemint.pcp.Compound.from_cid")
    def test_cli_lookup_success(self, mock_from_cid, runner, mock_chem_info, tmp_path):
        """Tests the 'chemint lookup' CLI command with successful data."""
        mock_compound = MagicMock()
        mock_compound.cid = mock_chem_info.cid
        mock_compound.molecular_formula = "CH2O"
        mock_compound.molecular_weight = mock_chem_info.molecular_weight
        mock_compound.iupac_name = mock_chem_info.iupac_name
        mock_compound.canonical_smiles = mock_chem_info.canonical_smiles
        mock_from_cid.return_value = mock_compound

        output_file = tmp_path / "chem_results.json"

        result = runner.invoke(
            chemint_app, ["lookup", "--cid", "240", "-o", str(output_file)]
        )

        assert result.exit_code == 0
        assert "Looking up chemical properties for CID: 240" in result.stdout
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["cid"] == 240


class TestPatentSearch:
    """Tests for the 'monitor-patents-research' command."""

    # --- FIX: Patched 'print' to check data, not rendered output ---
    @patch("chimera_intel.core.chemint.print")
    @patch("chimera_intel.core.chemint.pypatent.Search")
    @patch("chimera_intel.core.chemint.scholarly.search_pubs")
    def test_cli_patent_search_success(
        self,
        mock_search_pubs,
        mock_pypatent_search,
        mock_rich_print,  # <-- Added mock for 'print'
        runner,
        mock_patent_info,
    ):
        """Tests the 'chemint monitor-patents-research' CLI command."""

        # --- Arrange: Mock Patent Search ---
        mock_patent = MagicMock()
        mock_patent.title = mock_patent_info.title
        mock_patent.url = "http://example.com/patent"

        mock_search_instance = MagicMock()
        mock_search_instance.results = [mock_patent]
        mock_pypatent_search.return_value = mock_search_instance

        # --- Arrange: Mock Scholarly Search ---
        mock_pub = {
            "bib": {"title": "A great paper"},
            "eprint_url": "http://example.com/paper",
        }
        mock_search_pubs.return_value = iter([mock_pub])

        # --- Act ---
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "polymer"]
        )

        # --- Assert ---
        assert result.exit_code == 0

        # --- FIX: Check assertions against the mock_rich_print's call arguments ---
        # This robustly checks the *data* sent to print, bypassing render issues.

        # Capture all arguments passed to print()
        print_calls = mock_rich_print.call_args_list

        # Combine all arguments into a single string to check for section headers
        all_printed_text = ""
        printed_tables = []
        for call in print_calls:
            arg = call[0][0]  # Get the first positional argument of the print call
            if isinstance(arg, Table):
                printed_tables.append(arg)
            all_printed_text += str(arg)

        # Check that section titles were printed
        assert "Patents (USPTO)" in all_printed_text
        assert "Research Papers (Google Scholar)" in all_printed_text

        # Check that two tables were passed to print
        assert len(printed_tables) == 2

        # Check the data inside the tables
        patent_table = printed_tables[0]
        research_table = printed_tables[1]

        # Check patent table (accessing internal row data is fragile, but works)
        assert len(patent_table.rows) == 1
        # Get cell data from the first (and only) row
        patent_row_cells = [cell for cell in patent_table.rows[0].cells]
        assert mock_patent.title in patent_row_cells
        assert mock_patent.url in patent_row_cells

        # Check research table
        assert len(research_table.rows) == 1
        research_row_cells = [cell for cell in research_table.rows[0].cells]
        assert "A great paper" in research_row_cells
        assert "http://example.com/paper" in research_row_cells


class TestSdsAnalysis:
    """Tests for the 'analyze-sds' command."""

    # --- FIX: Corrected patch path ---
    @patch("chimera_intel.core.chemint.requests.get")
    def test_cli_sds_analysis_success(self, mock_get, runner, mock_sds_data, tmp_path):
        """Tests the 'chemint analyze-sds' CLI command."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "GHS02 H225 P210"
        mock_get.return_value = mock_response

        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds"]
        )

        assert result.exit_code == 0
        assert "Analyzing SDS from URL: http://example.com/sds" in result.stdout
        # These assertions are fine because the table contents are simple strings
        assert "GHS Pictograms" in result.stdout
        assert "GHS02" in result.stdout
        assert "Hazard Statements" in result.stdout
        assert "H225" in result.stdout
        assert "Precautionary Statements" in result.stdout
        assert "P210" in result.stdout