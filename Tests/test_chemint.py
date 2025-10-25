import pytest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from chimera_intel.core.chemint import chemint_app



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
    # Use mix_stderr=False (default) as we are only checking stdout
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

        assert result.exit_code == 0, f"CLI failed with: {result.stdout}"
        assert "Looking up chemical properties for CID: 240" in result.stdout
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["cid"] == 240


class TestPatentSearch:
    """
    Tests for the 'monitor-patents-research' command.
    """

    @patch("chimera_intel.core.chemint.pypatent.Search")
    @patch("chimera_intel.core.chemint.scholarly.search_pubs")
    def test_cli_patents_section_output(
        self, mock_scholarly_search, mock_pypatent_class, runner, mock_patent_info
    ):
        """
        Tests if the 'Patents (USPTO)' section renders correctly.
        This section correctly calls 'pypatent.Search'.
        """
        # 1. Define Mock Data
        patent_title = mock_patent_info.title
        patent_url = "http://example.com/patent"

        # 2. Configure Mocks
        
        class SimplePatentMock:
            pass
        
        mock_patent_obj = SimplePatentMock()
        mock_patent_obj.title = patent_title
        mock_patent_obj.url = patent_url

        # Mock for pypatent (this section's call)
        mock_pypatent_instance = MagicMock()

        mock_pypatent_instance.__iter__.return_value = iter([mock_patent_obj])

        mock_pypatent_class.return_value = mock_pypatent_instance

        mock_scholarly_search.return_value = iter([]) 

        # 3. Run CLI
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "polymer"]
        )
        stdout = result.stdout

        # 4. Assertions
        assert result.exit_code == 0
        assert "Patents (USPTO)" in stdout
        assert patent_title in stdout
        assert patent_url in stdout
        
        # Make sure research data (which would come from the other mock) isn't present
        assert "A great paper" not in stdout


    @patch("chimera_intel.core.chemint.pypatent.Search")
    @patch("chimera_intel.core.chemint.scholarly.search_pubs")
    def test_cli_research_section_output(
        self, mock_scholarly_search, mock_pypatent_class, runner
    ):
        """
        Tests if the 'Research Papers (Google Scholar)' section renders correctly.
        This section correctly calls 'scholarly.search_pubs'.
        """
        # 1. Define Mock Data
        research_title = "A great paper"
        research_url = "http://example.com/paper"

        # 2. Configure Mocks
        # Mock for scholarly (this section's call)
        mock_research_as_scholarly_dict = {
            "bib": {"title": research_title},
            "eprint_url": research_url
        }
        # The code iterates directly over the search_pubs result
        mock_scholarly_search.return_value = iter([mock_research_as_scholarly_dict])

        # Mock for pypatent (the other section's call, to avoid real requests)
        mock_pypatent_instance = MagicMock()
        # This .results = [] is fine, as it correctly results in an empty table.
        mock_pypatent_instance.results = [] 
        mock_pypatent_class.return_value = mock_pypatent_instance

        # 3. Run CLI
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "polymer"]
        )
        stdout = result.stdout

        # 4. Assertions
        assert result.exit_code == 0
        assert "Research Papers (Google Scholar)" in stdout
        assert research_title in stdout
        assert research_url in stdout
        
        # Make sure patent data (which would come from the other mock) isn't present
        assert "high-temperature resistant polymer" not in stdout

class TestSdsAnalysis:
    """Tests for the 'analyze-sds' command."""

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

        assert result.exit_code == 0, f"CLI failed with: {result.stdout}"
        assert "Analyzing SDS from URL: http://example.com/sds" in result.stdout
        # These assertions are fine because the table contents are simple strings
        assert "GHS Pictograms" in result.stdout
        assert "GHS02" in result.stdout
        assert "Hazard Statements" in result.stdout
        assert "H225" in result.stdout
        assert "Precautionary Statements" in result.stdout
        assert "P210" in result.stdout