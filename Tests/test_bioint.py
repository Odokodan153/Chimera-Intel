from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(mock_console_print, mock_entrez):
    # Mock esearch and efetch
    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock() # This handle is returned by efetch

    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.efetch.return_value = mock_efetch_handle

    # --- FIX ---
    # 1. Mock Entrez.read for the *single* esearch call.
    #    The source code only calls Entrez.read once.
    mock_entrez.read.return_value = {"IdList": ["12345", "67890"]}

    # 2. Mock the efetch_handle.read() method to return the raw GenBank text.
    #    This is what the source code (bioint.py) actually calls.
    mock_efetch_handle.read.return_value = (
        "LOCUS 12345\nDESCRIPTION Synthetic\nACCESSION 12345\n//\n"
        "LOCUS 67890\nDESCRIPTION Other\nACCESSION 67890\n//\n"
    )
    # --- END FIX ---

    # CLI invocation
    result = runner.invoke(
        bioint_app,
        [
            "--target",
            "CRISPR",
            "--email",
            "test@example.com",
            "--db",
            "GenBank",
        ],
    )

    # Assert success
    assert result.exit_code == 0, result.stdout
    
    # Check that console.print was called with the expected startup message
    mock_console_print.assert_any_call(
        "Monitoring [bold cyan]GenBank[/bold cyan] for target: '[yellow]CRISPR[/yellow]'"
    )
    # Check that console.print was called with the expected results
    mock_console_print.assert_any_call(
        "\n--- [bold green]Found 2 Matching Sequences[/bold green] ---"
    )
    # Check for the first record's ID
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 12345")
    # Check for the second record's ID
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 67890")


    # Verify Entrez calls
    mock_entrez.esearch.assert_called_with(db="nucleotide", term="CRISPR", retmax=5)
    
    # --- FIX ---
    # Assert Entrez.read was called *once* with the esearch handle.
    mock_entrez.read.assert_called_once_with(mock_esearch_handle)
    # --- END FIX ---
    
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )

    # --- FIX ---
    # Assert the efetch handle's read() method was called once.
    mock_efetch_handle.read.assert_called_once()
    # --- END FIX ---


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_no_results(mock_console_print, mock_entrez):
    # No results returned
    mock_esearch_handle = MagicMock()
    mock_entrez.esearch.return_value = mock_esearch_handle
    # This mock is fine as-is, as Entrez.read is called once for esearch.
    mock_entrez.read.return_value = {"IdList": []}

    # CLI invocation
    result = runner.invoke(
        bioint_app,
        [
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