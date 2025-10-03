import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@pytest.fixture
def mock_entrez(mocker):
    """Mocks the Bio.Entrez esearch and efetch calls."""
    mock_esearch_handle = MagicMock()
    mock_esearch_read = {"IdList": ["12345", "67890"]}

    mock_efetch_handle = MagicMock()
    # A minimal, valid GenBank record format

    mock_gb_record = (
        "LOCUS       12345               50 bp    DNA     linear   SYN 01-JAN-2023\n"
        "DESCRIPTION Synthetic construct.\n"
        "ACCESSION   12345\n"
        "//\n"
    )

    mock_entrez = MagicMock()
    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.read.return_value = mock_esearch_read
    mock_entrez.efetch.return_value = mock_efetch_handle

    # Patch the read method of the file-like handle returned by efetch

    mock_efetch_handle.read.return_value = mock_gb_record * 2

    return mocker.patch("chimera_intel.core.bioint.Entrez", mock_entrez)


def test_monitor_sequences_success(mock_entrez):
    """
    Tests the monitor-sequences command with a successful mock API response.
    """
    result = runner.invoke(
        bioint_app,
        ["monitor-sequences", "--target", "CRISPR", "--email", "test@example.com"],
    )

    assert result.exit_code == 0
    assert "Monitoring GenBank for target: 'CRISPR'" in result.stdout
    assert "Found 2 Matching Sequences" in result.stdout
    assert "Accession ID: 12345" in result.stdout

    # Verify Entrez was called with the correct parameters

    mock_entrez.esearch.assert_called_with(db="nucleotide", term="CRISPR", retmax=5)
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )


def test_monitor_sequences_no_results(mocker):
    """
    Tests the command's behavior when no sequences are found.
    """
    mock_esearch_read = {"IdList": []}
    mock_entrez = MagicMock()
    mock_entrez.esearch.return_value = MagicMock()
    mock_entrez.read.return_value = mock_esearch_read

    mocker.patch("chimera_intel.core.bioint.Entrez", mock_entrez)

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

    assert result.exit_code == 0
    assert "No matching sequences found." in result.stdout
