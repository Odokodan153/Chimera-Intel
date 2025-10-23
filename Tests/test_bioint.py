from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(mock_console_print, mock_entrez):
    # Mock esearch and efetch
    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock() # This handle is still returned by efetch

    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.efetch.return_value = mock_efetch_handle

    # --- PYTEST_FIX ---
    # Use side_effect to provide different return values for the two calls to Entrez.read
    # 1. The first call (for esearch) returns the ID list.
    # 2. The second call (for efetch) returns the raw sequence data.
    mock_entrez.read.side_effect = [
        {"IdList": ["12345", "67890"]},
        "LOCUS 12345\nDESCRIPTION Synthetic\nACCESSION 12345\n//" * 2
    ]
    # We no longer mock mock_efetch_handle.read, as Entrez.read(efetch_handle) is called instead.
    # --- END FIX ---

    # CLI invocation (This fix was from the previous step)
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
    
    # --- PYTEST_FIX ---
    # Change assertion to assert_any_call since Entrez.read is called twice,
    # and this is the first call.
    mock_entrez.read.assert_any_call(mock_esearch_handle)
    # We also assert that the second call to Entrez.read happened with the efetch handle
    mock_entrez.read.assert_any_call(mock_efetch_handle)
    # --- END FIX ---
    
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_no_results(mock_console_print, mock_entrez):
    # No results returned
    mock_esearch_handle = MagicMock()
    mock_entrez.esearch.return_value = mock_esearch_handle
    # This mock is fine as-is, because Entrez.read is only called once
    # before the function returns.
    mock_entrez.read.return_value = {"IdList": []}

    # CLI invocation (This fix was from the previous step)
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