# Chimera-Intel/Tests/test_qint.py
import pytest
import requests
from typer.testing import CliRunner
from unittest.mock import patch, Mock

# The application instance to be tested
from chimera_intel.core.qint import app as qint_app, QInt

runner = CliRunner()


@pytest.fixture
def qint_instance():
    return QInt()


# --- Unit Tests for QInt Class ---


@patch("chimera_intel.core.qint.feedparser.parse")
def test_scrape_quantum_research_success(mock_parse, qint_instance):
    """Tests successful research scraping."""
    # Fix: Use explicit attribute assignment for a robust mock,
    # preventing an exception when accessing 'author.name'
    mock_author = Mock()
    mock_author.name = "Dr. Test"

    mock_entry = Mock()
    mock_entry.title = "Test Paper"
    mock_entry.authors = [mock_author]
    mock_entry.published = "2023-01-01T12:00:00Z"
    mock_entry.link = "http://example.com"
    mock_parse.return_value = Mock(entries=[mock_entry])

    papers = qint_instance.scrape_quantum_research("quantum", max_results=1)

    assert len(papers) == 1
    assert papers[0]["title"] == "Test Paper"
    assert papers[0]["authors"] == "Dr. Test"


@patch(
    "chimera_intel.core.qint.feedparser.parse", side_effect=Exception("ArXiv is down")
)
def test_scrape_quantum_research_exception(mock_parse, qint_instance, capsys):
    """Tests exception handling during research scraping."""
    papers = qint_instance.scrape_quantum_research("quantum", max_results=1)

    assert papers == []
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output, as rich markup is stripped by capsys
    assert "Error scraping arXiv: ArXiv is down\n" == captured.out


@patch("chimera_intel.core.qint.requests.get")
def test_analyze_trl_heuristics(mock_get, qint_instance):
    """Tests the different TRL heuristic branches."""

    # Test TRL 8 (quantum supremacy)
    mock_response = Mock()
    mock_response.content = "<html><body>quantum supremacy achieved</body></html>"
    mock_get.return_value = mock_response
    result = qint_instance.analyze_trl("Google")
    assert result["estimated_trl"] == 8

    # Test TRL 7 (qubit roadmap)
    mock_response.content = "<html><body>our qubit roadmap is public</body></html>"
    mock_get.return_value = mock_response
    result = qint_instance.analyze_trl("IBM")
    assert result["estimated_trl"] == 7

    # Test TRL 6 (qkd)
    mock_response.content = (
        "<html><body>we focus on qkd and quantum sensing</body></html>"
    )
    mock_get.return_value = mock_response
    result = qint_instance.analyze_trl("Toshiba")
    assert result["estimated_trl"] == 6

    # Test TRL 5 (funding)
    mock_response.content = "<html><body>a new funding initiative</body></html>"
    mock_get.return_value = mock_response
    result = qint_instance.analyze_trl("Startup")
    assert result["estimated_trl"] == 5

    # Test TRL 3 (baseline)
    mock_response.content = "<html><body>nothing special here</body></html>"
    mock_get.return_value = mock_response
    result = qint_instance.analyze_trl("Unknown")
    assert result["estimated_trl"] == 3


@patch(
    "chimera_intel.core.qint.requests.get",
    side_effect=requests.RequestException("Network error"),
)
def test_analyze_trl_exception(mock_get, qint_instance, capsys):
    """Tests exception handling for TRL analysis."""
    result = qint_instance.analyze_trl("Google")
    assert "error" in result
    assert result["error"] == "Could not perform TRL analysis."
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output
    assert "Error analyzing TRL for Google: Network error\n" == captured.out


@patch("chimera_intel.core.qint.requests.get")
def test_monitor_pqc_success(mock_get, qint_instance):
    """Tests successful PQC monitoring."""
    html_content = """
    <html><body>
    <table caption="Algorithms to be Standardized">
      <tbody>
        <tr><td>CRYSTALS-Kyber</td><td>KEM</td></tr>
        <tr><td>CRYSTALS-Dilithium</td><td>Digital Signature</td></tr>
      </tbody>
    </table>
    </body></html>
    """
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.content = html_content
    mock_get.return_value = mock_response

    algorithms = qint_instance.monitor_pqc()

    assert len(algorithms) == 2
    assert algorithms[0]["algorithm"] == "CRYSTALS-Kyber"
    assert algorithms[1]["type"] == "Digital Signature"
    assert algorithms[1]["status"] == "Selected for Standardization"


@patch("chimera_intel.core.qint.requests.get")
def test_monitor_pqc_table_not_found(mock_get, qint_instance):
    """Tests PQC monitoring when the table is not found."""
    html_content = "<html><body>No table here</body></html>"
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.content = html_content
    mock_get.return_value = mock_response

    algorithms = qint_instance.monitor_pqc()
    assert algorithms == []


@patch(
    "chimera_intel.core.qint.requests.get",
    side_effect=requests.RequestException("NIST is down"),
)
def test_monitor_pqc_exception(mock_get, qint_instance, capsys):
    """Tests exception handling for PQC monitoring."""
    algorithms = qint_instance.monitor_pqc()
    assert algorithms == []
    captured = capsys.readouterr()
    # Fix: Check for the exact plain text output
    assert "Error scraping NIST PQC page: NIST is down\n" == captured.out


# --- CLI Tests ---


@patch("chimera_intel.core.qint.QInt.scrape_quantum_research")
def test_cli_research_success(mock_scrape):
    """Tests the 'research' command with results."""
    mock_scrape.return_value = [
        {
            "title": "Paper 1",
            "authors": "Author A",
            "published": "2023-01-01T00:00:00Z",
            "link": "link1",
        },
        {
            "title": "Paper 2",
            "authors": "Author B",
            "published": "2023-01-02T00:00:00Z",
            "link": "link2",
        },
    ]

    result = runner.invoke(qint_app, ["research", "test", "--limit", "2"])

    assert result.exit_code == 0

    # --- FIX: Check for substrings, as rich.Table formats the title ---
    assert "Recent Research on 'test'" in result.stdout
    assert "arXiv" in result.stdout
    # --- End Fix ---

    assert "Paper 1" in result.stdout
    assert "Author B" in result.stdout
    mock_scrape.assert_called_with("test", 2)


@patch("chimera_intel.core.qint.QInt.scrape_quantum_research", return_value=[])
def test_cli_research_no_results(mock_scrape):
    """Tests the 'research' command with no results."""
    result = runner.invoke(qint_app, ["research", "xyz"])
    assert result.exit_code == 0
    assert "Recent Research" not in result.stdout  # Table shouldn't be printed


@patch("chimera_intel.core.qint.QInt.analyze_trl")
def test_cli_trl_analysis(mock_analyze):
    """Tests the 'trl-analysis' command."""
    mock_analyze.return_value = {
        "entity": "TestCorp",
        "estimated_trl": 7,
        "assessment": "Good progress.",
    }

    result = runner.invoke(qint_app, ["trl-analysis", "TestCorp"])

    assert result.exit_code == 0
    assert '"entity": "TestCorp"' in result.stdout
    assert '"estimated_trl": 7' in result.stdout
    mock_analyze.assert_called_with("TestCorp")


@patch("chimera_intel.core.qint.QInt.monitor_pqc")
def test_cli_pqc_status_success(mock_monitor):
    """Tests the 'pqc-status' command with results."""
    mock_monitor.return_value = [
        {"algorithm": "Kyber", "type": "KEM", "status": "Selected"},
    ]

    result = runner.invoke(qint_app, ["pqc-status"])

    assert result.exit_code == 0
    # Fix: Check for a robust substring of the title due to rich table formatting
    assert "NIST Post-Quantum Cryptography" in result.stdout
    assert "Kyber" in result.stdout
    assert "KEM" in result.stdout


@patch("chimera_intel.core.qint.QInt.monitor_pqc", return_value=[])
def test_cli_pqc_status_no_results(mock_monitor):
    """Tests the 'pqc-status' command with no results."""
    result = runner.invoke(qint_app, ["pqc-status"])
    assert result.exit_code == 0
    assert "NIST Post-Quantum Cryptography" not in result.stdout  # Table not printed
