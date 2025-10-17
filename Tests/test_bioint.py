import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch

# The application instance to be tested

from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@pytest.fixture
def mock_entrez(mocker):
    """Mocks the Bio.Entrez esearch and efetch calls."""
    # 1. Create a mock for the entire Entrez module

    mock_entrez_module = MagicMock()

    # 2. Mock the handles that are returned by esearch and efetch

    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock()

    # 3. Define the return values for the mocked calls

    mock_esearch_read_result = {"IdList": ["12345", "67890"]}
    mock_gb_record = (
        "LOCUS       12345               50 bp    DNA     linear   SYN 01-JAN-2023\n"
        "DESCRIPTION Synthetic construct.\n"
        "ACCESSION   12345\n"
        "//\n"
    )

    # 4. Configure the mocks

    mock_entrez_module.esearch.return_value = mock_esearch_handle
    # Correctly mock Entrez.read as a function that returns the desired dictionary

    mock_entrez_module.read.return_value = mock_esearch_read_result

    mock_entrez_module.efetch.return_value = mock_efetch_handle
    # The read() method of the efetch handle returns the record text

    mock_efetch_handle.read.return_value = mock_gb_record * 2

    # 5. Patch the Entrez module in the bioint script

    mocker.patch("chimera_intel.core.bioint.Entrez", mock_entrez_module)

    # Return the configured module mock for assertions in the test

    return mock_entrez_module


def test_monitor_sequences_success(mock_entrez):
    """
    Tests the monitor-sequences command with a successful mock API response.
    """
    result = runner.invoke(
        bioint_app,
        ["monitor-sequences", "--target", "CRISPR", "--email", "test@example.com"],
    )

    assert result.exit_code == 0, result.stdout
    assert "Monitoring GenBank for target: 'CRISPR'" in result.stdout
    assert "Found 2 Matching Sequences" in result.stdout
    assert "Accession ID: 12345" in result.stdout

    # Verify Entrez was called with the correct parameters

    mock_entrez.esearch.assert_called_with(db="nucleotide", term="CRISPR", retmax=5)
    mock_entrez.read.assert_called_with(mock_entrez.esearch.return_value)
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )


@patch("chimera_intel.core.bioint.Entrez")
def test_monitor_sequences_no_results(mock_entrez):
    """
    Tests the command's behavior when no sequences are found.
    """
    # Configure the mock for the no-results scenario

    mock_entrez.esearch.return_value = MagicMock()
    mock_entrez.read.return_value = {"IdList": []}

    result = runner.invoke(
        bioint_app,
        [
            "monitor-sequences",
            "--target",
            "unknown_sequence",
            "--email",
            "test@example.com",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert "No matching sequences found." in result.stdout
    # Ensure efetch is not called when there are no IDs

    mock_entrez.efetch.assert_not_called()
