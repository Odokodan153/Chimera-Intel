import pytest
from typer.testing import CliRunner

# The application instance to be tested
from chimera_intel.core.cytech_intel import cytech_intel_app

# The tool to be mocked
import chimera_intel.core.cytech_intel

runner = CliRunner()


@pytest.fixture
def mock_google_search(mocker):
    """Mocks the google_search function."""
    return mocker.patch(
        "chimera_intel.core.cytech_intel.google_search",
        return_value=[
            {
                "title": "Mocked Search Result",
                "url": "https://example.com",
                "snippet": "This is a mocked search result snippet.",
            }
        ],
    )


def test_emerging_tech_success(mock_google_search):
    """
    Tests the emerging-tech command with a successful search.
    """
    result = runner.invoke(
        cytech_intel_app, ["emerging-tech", "--domain", "AI", "--topic", "robotics"]
    )

    assert result.exit_code == 0, result.output
    assert "Tracking emerging tech in [bold]AI[/bold] on topic: [bold]robotics[/bold]" in result.output
    assert "Title: Mocked Search Result" in result.output
    assert "URL: https://example.com" in result.output


def test_malware_sandbox_success(mock_google_search):
    """
    Tests the malware-sandbox command with a successful search.
    """
    test_hash = "e4d909c290d0fb1ca068ffaddf22cbd0"
    result = runner.invoke(
        cytech_intel_app, ["malware-sandbox", "--indicator", test_hash]
    )

    assert result.exit_code == 0, result.output
    assert f"Analyzing malware indicator: {test_hash}" in result.output
    assert "--- Found Public Analysis Reports ---" in result.output
    assert "Title: Mocked Search Result" in result.output


def test_vulnerability_hunter_success(mock_google_search):
    """
    Tests the vuln-hunter command with a successful search.
    """
    product = "Microsoft Exchange"
    result = runner.invoke(
        cytech_intel_app, ["vuln-hunter", "--product", product]
    )

    assert result.exit_code == 0, result.output
    assert f"Hunting for recent vulnerabilities in: {product}" in result.output
    assert "--- Recent Vulnerability & Exploit News ---" in result.output
    assert "Snippet: This is a mocked search result snippet." in result.output


def test_emerging_tech_no_results(mocker):
    """
    Tests the emerging-tech command when no results are found.
    """
    mocker.patch(
        "chimera_intel.core.cytech_intel.google_search", return_value=[]
    )
    result = runner.invoke(
        cytech_intel_app, ["emerging-tech", "--domain", "Quantum", "--topic", "teleportation"]
    )
    assert result.exit_code == 0, result.output
    assert "No results found." in result.output


def test_malware_sandbox_no_results(mocker):
    """
    Tests the malware-sandbox command when no results are found.
    """
    mocker.patch(
        "chimera_intel.core.cytech_intel.google_search", return_value=[]
    )
    result = runner.invoke(
        cytech_intel_app, ["malware-sandbox", "--indicator", "nonexistent_hash"]
    )
    assert result.exit_code == 0, result.output
    assert "No public reports found for: nonexistent_hash" in result.output


def test_vulnerability_hunter_no_results(mocker):
    """
    Tests the vuln-hunter command when no results are found.
    """
    mocker.patch(
        "chimera_intel.core.cytech_intel.google_search", return_value=[]
    )
    result = runner.invoke(
        cytech_intel_app, ["vuln-hunter", "--product", "FakeProduct 1.0"]
    )
    assert result.exit_code == 0, result.output
    assert "No recent vulnerability news found for: FakeProduct 1.0" in result.output

def test_google_search_api_error(mocker):
    """
    Tests that a generic exception from the search tool is caught.
    """
    mocker.patch(
        "chimera_intel.core.cytech_intel.google_search",
        side_effect=Exception("API limit reached"),
    )
    result = runner.invoke(
        cytech_intel_app, ["vuln-hunter", "--product", "Test"]
    )
    assert result.exit_code == 1, result.output
    assert "An unexpected error occurred: API limit reached" in result.output