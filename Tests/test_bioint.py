from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(mock_console_print, mock_entrez):
    # Mock esearch and efetch
    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock()

    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.read.return_value = {"IdList": ["12345", "67890"]}
    mock_entrez.efetch.return_value = mock_efetch_handle
    mock_efetch_handle.read.return_value = (
        "LOCUS 12345\nDESCRIPTION Synthetic\nACCESSION 12345\n//" * 2
    )

    # CLI invocation
    result = runner.invoke(
        bioint_app,
        [
            "monitor-sequences",
            "--target",
            "CRISPR",
            "--email",
            "test@example.com",
            "--db",
            "GenBank",
        ],
    )

    assert result.exit_code == 0, result.stdout
    
    # Check that console.print was called with the expected startup message
    mock_console_print.assert_any_call(
        "Monitoring [bold cyan]GenBank[/bold cyan] for target: '[yellow]CRISPR[/yellow]'"
    )
    # Check that console.print was called with the expected results
    mock_console_print.assert_any_call(
        "\n--- [bold green]Found 2 Matching Sequences[/bold green] ---"
    )
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 12345")


    # Verify Entrez calls
    mock_entrez.esearch.assert_called_with(db="nucleotide", term="CRISPR", retmax=5)
    mock_entrez.read.assert_called_with(mock_esearch_handle)
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_no_results(mock_console_print, mock_entrez):
    # No results returned
    mock_esearch_handle = MagicMock()
    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.read.return_value = {"IdList": []}

    result = runner.invoke(
        bioint_app,
        [
            "monitor-sequences",
            "--target",
            "unknown_sequence",
            "--email",
            "test@example.com",
            "--db",
            "GenBank",
        ],
    )

    assert result.exit_code == 0
    mock_console_print.assert_any_call("[yellow]No matching sequences found.[/yellow]")
    mock_entrez.efetch.assert_not_called()