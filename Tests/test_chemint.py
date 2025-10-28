import pytest
import json
import re
import requests
from unittest.mock import patch, MagicMock, ANY
from typer.testing import CliRunner
from chimera_intel.core.chemint import chemint_app

# ------------------
# Pytest Fixtures
# ------------------

@pytest.fixture
def runner():
    """Provides a Typer CliRunner instance."""
    return CliRunner()

# ------------------
# MOCK DATA
# ------------------

@pytest.fixture
def mock_pypatent_result():
    """Mock data for a pypatent search result."""
    mock_patent = MagicMock()
    mock_patent.title = "Test Patent Title"
    mock_patent.url = "http://example.com/patent1"
    return [mock_patent]

@pytest.fixture
def mock_scholarly_result():
    """Mock data for a scholarly search result."""
    return [
        {
            "bib": {"title": "Test Paper Title"},
            "eprint_url": "http://example.com/paper1"
        }
    ]

# Mock HTML for track-precursors
MOCK_HTML_SIGMA = """
<li class="list-group-item">
    <a class="product-name">Sigma Product</a>
    <span class="price">$100.00</span>
</li>
"""
MOCK_HTML_FISHER = """
<div class="product_pod">
    <a class="title-link">Fisher Product</a>
    <span class="price_value">$200.00</span>
</div>
"""
MOCK_HTML_VWR = """
<div class="search-item">
    <a class="search-item__title">VWR Product</a>
    <span class="search-item__price">$300.00</span>
</div>
"""

# Mock HTML for monitor-chemical-news
MOCK_HTML_CEN = """
<div class="search-result">
    <a href="/relative/path/cen">C&EN Article</a>
</div>
"""
MOCK_HTML_CHEMISTRY_WORLD = """
<div class="story-listing-item">
    <a href="https://www.chemistryworld.com/absolute/path">Chemistry World Article</a>
</div>
"""
MOCK_HTML_ICIS = """
<article>
    <a href="/relative/path/icis">ICIS Article</a>
</article>
"""

# ------------------
# Test Suites
# ------------------

class TestChemicalLookup:
    """Tests for the 'lookup' command."""

    @patch("chimera_intel.core.chemint.pcp.Compound.from_cid")
    def test_cli_lookup_success_with_output(self, mock_from_cid, runner, tmp_path):
        """Tests the 'chemint lookup' CLI command with successful data and file output."""
        # Arrange
        mock_compound = MagicMock()
        mock_compound.cid = 240
        mock_compound.molecular_formula = "CH2O"
        mock_compound.molecular_weight = 30.03
        mock_compound.iupac_name = "Formaldehyde"
        mock_compound.canonical_smiles = "C=O"
        mock_from_cid.return_value = mock_compound

        output_file = tmp_path / "chem_results.json"

        # Act
        result = runner.invoke(
            chemint_app, ["lookup", "--cid", "240", "-o", str(output_file)]
        )

        # Assert
        assert result.exit_code == 0
        assert "Looking up chemical properties for CID: 240" in result.stdout
        assert "molecular_formula" in result.stdout
        assert "CH2O" in result.stdout
        assert "Results saved to" in result.stdout
        
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["results"][0]["cid"] == 240
            assert data["results"][0]["iupac_name"] == "Formaldehyde"

    @patch("chimera_intel.core.chemint.pcp.Compound.from_cid")
    def test_cli_lookup_success_no_output(self, mock_from_cid, runner, tmp_path):
        """Tests the 'chemint lookup' command without an output file."""
        # Arrange
        mock_compound = MagicMock()
        mock_compound.cid = 240
        mock_compound.molecular_formula = "CH2O"
        mock_compound.molecular_weight = 30.03
        mock_compound.iupac_name = "Formaldehyde"
        mock_compound.canonical_smiles = "C=O"
        mock_from_cid.return_value = mock_compound

        # Act
        result = runner.invoke(chemint_app, ["lookup", "--cid", "240"])

        # Assert
        assert result.exit_code == 0
        assert "Looking up chemical properties for CID: 240" in result.stdout
        assert "molecular_formula" in result.stdout
        assert "CH2O" in result.stdout
        assert "Results saved to" not in result.stdout # Key assertion

    @patch("chimera_intel.core.chemint.pcp.Compound.from_cid", side_effect=Exception("PubChem Error"))
    def test_cli_lookup_exception(self, mock_from_cid, runner):
        """Tests the exception handler for the 'lookup' command."""
        # Act
        result = runner.invoke(chemint_app, ["lookup", "--cid", "999"])

        # Assert
        assert result.exit_code == 0 # The exception is caught and printed
        assert "Error looking up chemical properties: PubChem Error" in result.stdout

class TestPatentSearch:
    """Tests for the 'monitor-patents-research' command."""

    @patch("chimera_intel.core.chemint.scholarly.search_pubs", return_value=iter([]))
    @patch("chimera_intel.core.chemint.pypatent.Search")
    def test_patents_found_success(self, mock_pypatent_class, mock_scholarly, runner, mock_pypatent_result):
        """Tests the happy path when patents are found."""
        # Arrange
        mock_instance = MagicMock()
        mock_instance.results = mock_pypatent_result
        mock_pypatent_class.return_value = mock_instance

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "polymer"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Patents (USPTO):" in result.stdout
        assert "Test Patent Title" in result.stdout
        assert "http://example.com/patent1" in result.stdout
        assert "No patents found on USPTO." not in result.stdout

    @patch("chimera_intel.core.chemint.scholarly.search_pubs", return_value=iter([]))
    @patch("chimera_intel.core.chemint.pypatent.Search")
    def test_patents_found_callable(self, mock_pypatent_class, mock_scholarly, runner, mock_pypatent_result):
        """Tests the path where pypatent.results is a callable."""
        # Arrange
        mock_instance = MagicMock()
        # Mock .results to be a callable function
        mock_instance.results = MagicMock(return_value=mock_pypatent_result)
        mock_pypatent_class.return_value = mock_instance

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "polymer"]
        )
        
        # Assert
        assert result.exit_code == 0
        mock_instance.results.assert_called_once() # Check that the callable was called
        assert "Test Patent Title" in result.stdout

    @patch("chimera_intel.core.chemint.scholarly.search_pubs", return_value=iter([]))
    @patch("chimera_intel.core.chemint.pypatent.Search")
    def test_no_patents_found(self, mock_pypatent_class, mock_scholarly, runner):
        """Test CLI behavior when no patents are found."""
        # Arrange
        mock_instance = MagicMock()
        mock_instance.results = []
        mock_pypatent_class.return_value = mock_instance

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "nonexistent"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Patents (USPTO):" in result.stdout
        assert "No patents found on USPTO." in result.stdout

    @patch("chimera_intel.core.chemint.scholarly.search_pubs", return_value=iter([]))
    @patch("chimera_intel.core.chemint.pypatent.Search", side_effect=Exception("USPTO API Down"))
    def test_pypatent_exception(self, mock_pypatent_class, mock_scholarly, runner):
        """Tests the exception handler for the pypatent search."""
        # Act
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "error"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error searching for patents on USPTO: USPTO API Down" in result.stdout

    @patch("chimera_intel.core.chemint.scholarly.search_pubs", side_effect=Exception("Google Scholar Blocked"))
    @patch("chimera_intel.core.chemint.pypatent.Search")
    def test_scholarly_exception(self, mock_pypatent_class, mock_scholarly, runner):
        """Tests the exception handler for the scholarly search."""
        # Arrange
        mock_instance = MagicMock()
        mock_instance.results = []
        mock_pypatent_class.return_value = mock_instance

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-patents-research", "--keywords", "error"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error searching for research papers: Google Scholar Blocked" in result.stdout
        assert "Note: Google Scholar may block requests." in result.stdout

class TestTrackPrecursors:
    """Tests for the 'track-precursors' command (previously uncovered)."""

    @patch("chimera_intel.core.chemint.requests.get")
    def test_track_precursors_success(self, mock_get, runner, tmp_path):
        """Tests happy path for all three suppliers and CSV writing."""
        # Arrange
        output_file = tmp_path / "precursors.csv"
        
        def mock_response(*args, **kwargs):
            url = args[0]
            response = MagicMock()
            response.status_code = 200
            if "sigmaaldrich" in url:
                response.text = MOCK_HTML_SIGMA
            elif "fishersci" in url:
                response.text = MOCK_HTML_FISHER
            elif "vwr" in url:
                response.text = MOCK_HTML_VWR
            else:
                response.text = ""
            return response
        
        mock_get.side_effect = mock_response

        # Act
        result = runner.invoke(
            chemint_app, ["track-precursors", "-p", "acetone", "-o", str(output_file)]
        )

        # Assert
        assert result.exit_code == 0
        assert "Tracking precursors: acetone" in result.stdout
        assert "Scraped Sigma-Aldrich for acetone" in result.stdout
        assert "Scraped Fisher Scientific for acetone" in result.stdout
        assert "Scraped VWR for acetone" in result.stdout
        
        # FIX: Split assertion to be robust to newlines in the output
        assert "Precursor tracking data saved to" in result.stdout
        assert str(output_file) in result.stdout

        # Check CSV content
        with open(output_file, "r") as f:
            content = f.read()
            assert "Supplier,Precursor,Product Name,Price,URL" in content
            assert "Sigma-Aldrich,acetone,Sigma Product,$100.00" in content
            assert "Fisher Scientific,acetone,Fisher Product,$200.00" in content
            assert "VWR,acetone,VWR Product,$300.00" in content

    @patch("chimera_intel.core.chemint.requests.get")
    def test_track_precursors_no_results(self, mock_get, runner, tmp_path):
        """Tests the path where no products are found."""
        # Arrange
        output_file = tmp_path / "precursors.csv"
        mock_response = MagicMock(status_code=200, text="<html>No results</html>")
        mock_get.return_value = mock_response

        # Act
        result = runner.invoke(
            chemint_app, ["track-precursors", "-p", "nonexistent", "-o", str(output_file)]
        )

        # Assert
        assert result.exit_code == 0
        assert "No precursor data was found." in result.stdout
        assert not output_file.exists()

    @patch("chimera_intel.core.chemint.requests.get", side_effect=requests.exceptions.RequestException("Connection Timeout"))
    def test_track_precursors_request_exception(self, mock_get, runner, tmp_path):
        """Tests the requests exception handler."""
        # Arrange
        output_file = tmp_path / "precursors.csv"

        # Act
        result = runner.invoke(
            chemint_app, ["track-precursors", "-p", "acetone", "-o", str(output_file)]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error scraping Sigma-Aldrich: Connection Timeout" in result.stdout
        assert "No precursor data was found." in result.stdout

    @patch("chimera_intel.core.chemint.requests.get")
    @patch("chimera_intel.core.chemint.BeautifulSoup", side_effect=Exception("Parsing Error"))
    def test_track_precursors_parsing_exception(self, mock_soup, mock_get, runner, tmp_path):
        """Tests the generic exception handler (e.g., parsing error)."""
        # Arrange
        output_file = tmp_path / "precursors.csv"
        mock_get.return_value = MagicMock(status_code=200, text="<html></html>")

        # Act
        result = runner.invoke(
            chemint_app, ["track-precursors", "-p", "acetone", "-o", str(output_file)]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error parsing Sigma-Aldrich data: Parsing Error" in result.stdout
        assert "No precursor data was found." in result.stdout

class TestSdsAnalysis:
    """Tests for the 'analyze-sds' command."""

    @patch("chimera_intel.core.chemint.requests.get")
    def test_cli_sds_analysis_html(self, mock_get, runner):
        """Tests the 'analyze-sds' command with HTML content (existing test)."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "GHS02 H225 P210"
        mock_get.return_value = mock_response

        # Act
        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds.html"]
        )

        # Assert
        assert result.exit_code == 0
        assert "Analyzing SDS from URL: http://example.com/sds.html" in result.stdout
        assert "GHS Pictograms" in result.stdout
        assert "GHS02" in result.stdout
        assert "H225" in result.stdout
        assert "P210" in result.stdout

    @patch("chimera_intel.core.chemint.docx.Document")
    @patch("chimera_intel.core.chemint.requests.get")
    def test_cli_sds_analysis_docx(self, mock_get, mock_docx, runner):
        """Tests the 'analyze-sds' command with DOCX content."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
        mock_response.content = b"fake-docx-bytes"
        mock_get.return_value = mock_response

        mock_para = MagicMock()
        mock_para.text = "This is a DOCX. GHS05 H314 P280"
        mock_doc = MagicMock()
        mock_doc.paragraphs = [mock_para]
        mock_docx.return_value = mock_doc

        # Act
        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds.docx"]
        )

        # Assert
        assert result.exit_code == 0
        # FIX: Use mock.ANY as BytesIO objects are distinct instances even with identical content.
        mock_docx.assert_called_once_with(ANY)
        assert "GHS05" in result.stdout
        assert "H314" in result.stdout
        assert "P280" in result.stdout

    @patch("chimera_intel.core.chemint.pdfplumber.open")
    @patch("chimera_intel.core.chemint.requests.get")
    def test_cli_sds_analysis_pdf(self, mock_get, mock_pdfplumber, runner):
        """Tests the 'analyze-sds' command with PDF content."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pdf"}
        mock_response.content = b"fake-pdf-bytes"
        mock_get.return_value = mock_response

        mock_page = MagicMock()
        mock_page.extract_text.return_value = "This is a PDF. GHS07 H302 P301"
        mock_pdf = MagicMock()
        mock_pdf.pages = [mock_page]
        mock_pdf.__enter__.return_value = mock_pdf
        mock_pdf.__exit__.return_value = None
        mock_pdfplumber.return_value = mock_pdf

        # Act
        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds.pdf"]
        )

        # Assert
        assert result.exit_code == 0
        # FIX: Use mock.ANY as BytesIO objects are distinct instances even with identical content.
        mock_pdfplumber.assert_called_once_with(ANY)
        assert "GHS07" in result.stdout
        assert "H302" in result.stdout
        assert "P301" in result.stdout

    @patch("chimera_intel.core.chemint.requests.get", side_effect=requests.exceptions.RequestException("Download Failed"))
    def test_cli_sds_analysis_download_error(self, mock_get, runner):
        """Tests the download exception handler for 'analyze-sds'."""
        # Act
        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds.pdf"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error downloading SDS: Download Failed" in result.stdout

    @patch("chimera_intel.core.chemint.requests.get")
    @patch("chimera_intel.core.chemint.pdfplumber.open", side_effect=Exception("Corrupt PDF"))
    def test_cli_sds_analysis_generic_error(self, mock_pdfplumber, mock_get, runner):
        """Tests the generic exception handler for 'analyze-sds'."""
        # Arrange
        mock_response = MagicMock(status_code=200, headers={"Content-Type": "application/pdf"}, content=b"fake")
        mock_get.return_value = mock_response

        # Act
        result = runner.invoke(
            chemint_app, ["analyze-sds", "--sds-url", "http://example.com/sds.pdf"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "An unexpected error occurred: Corrupt PDF" in result.stdout

class TestMonitorChemicalNews:
    """Tests for the 'monitor-chemical-news' command (previously uncovered)."""

    @patch("chimera_intel.core.chemint.requests.get")
    def test_monitor_news_success(self, mock_get, runner):
        """Robust happy path test for chemical news monitoring."""
        # Arrange: return HTML snippets depending on the URL
        def mock_response(*args, **kwargs):
            url = args[0]
            response = MagicMock(status_code=200)
            if "cen.acs.org" in url:
                response.text = MOCK_HTML_CEN
            elif "chemistryworld.com" in url:
                response.text = MOCK_HTML_CHEMISTRY_WORLD
            elif "icis.com" in url:
                response.text = MOCK_HTML_ICIS
            else:
                response.text = ""
            return response
        
        mock_get.side_effect = mock_response

        # Act
        result = runner.invoke(chemint_app, ["monitor-chemical-news", "-k", "polymer"])

        # Assert
        assert result.exit_code == 0
        output = result.stdout

        # Check header
        assert "Monitoring chemical news for keywords: polymer" in output

        # Check that each source name and at least one article title is present
        sources_and_titles = [
            ("Chemical & Engineering News", "C&EN Article"),
            ("Chemistry World", "Chemistry World Article"),
            ("ICIS", "ICIS Article")
        ]
        for source, title in sources_and_titles:
            assert source in output
            assert title in output

        # Optional: check that a URL-like string exists for each article
        url_pattern = r"https?://[^\s]+|/[^ \n]+"
        urls_found = re.findall(url_pattern, output)
        assert len(urls_found) >= 3  # At least one URL per source

    @patch("chimera_intel.core.chemint.requests.get")
    def test_monitor_news_no_results(self, mock_get, runner):
        """Tests the path where no news articles are found."""
        # Arrange
        mock_get.return_value = MagicMock(status_code=200, text="<html>No results</html>")

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-chemical-news", "-k", "nonexistent"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "No chemical news found." in result.stdout

    @patch("chimera_intel.core.chemint.requests.get", side_effect=requests.exceptions.RequestException("Connection Failed"))
    def test_monitor_news_request_exception(self, mock_get, runner):
        """Tests the requests exception handler."""
        # Act
        result = runner.invoke(
            chemint_app, ["monitor-chemical-news", "-k", "error"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error scraping Chemical & Engineering News: Connection Failed" in result.stdout
        assert "No chemical news found." in result.stdout

    @patch("chimera_intel.core.chemint.requests.get")
    @patch("chimera_intel.core.chemint.BeautifulSoup", side_effect=Exception("Parsing Error"))
    def test_monitor_news_parsing_exception(self, mock_soup, mock_get, runner):
        """Tests the generic exception handler (e.g., parsing error)."""
        # Arrange
        mock_get.return_value = MagicMock(status_code=200, text="<html></html>")

        # Act
        result = runner.invoke(
            chemint_app, ["monitor-chemical-news", "-k", "error"]
        )
        
        # Assert
        assert result.exit_code == 0
        assert "Error parsing Chemical & Engineering News data: Parsing Error" in result.stdout
        assert "No chemical news found." in result.stdout