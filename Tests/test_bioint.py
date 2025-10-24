from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


# --- FIX 1: Add a patch for SeqIO.parse ---
@patch("chimera_intel.core.bioint.SeqIO.parse")
@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(
    mock_console_print, mock_entrez, mock_seqio_parse  # --- FIX 2: Add mock_seqio_parse arg ---
):
    # Mock esearch and efetch
    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock()  # This handle is returned by efetch

    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.efetch.return_value = mock_efetch_handle

    # 1. Mock Entrez.read for the *single* esearch call.
    mock_entrez.read.return_value = {"IdList": ["12345", "67890"]}

    # 2. Mock the efetch_handle.read() method to return raw text.
    #    This text no longer needs to be perfectly formatted,
    #    as SeqIO.parse is now mocked.
    mock_efetch_handle.read.return_value = "Mocked GenBank text data"

    # --- FIX 3: Configure SeqIO.parse to return mock records ---
    # Create mock records that the main code will iterate over
    mock_record_1 = MagicMock()
    mock_record_1.id = "12345"
    mock_record_1.description = "Synthetic construct"
    mock_record_1.seq = "ATCG"  # Just needs to have a len()

    mock_record_2 = MagicMock()
    mock_record_2.id = "67890"
    mock_record_2.description = "Another sequence"
    mock_record_2.seq = "GATTACA"

    # Set the return value for SeqIO.parse
    mock_seqio_parse.return_value = [mock_record_1, mock_record_2]
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
    # Check for the first record's details
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 12345")
    mock_console_print.assert_any_call("  [bold]Description:[/] Synthetic construct")
    mock_console_print.assert_any_call("  [bold]Sequence Length:[/] 4 bp")
    
    # Check for the second record's details
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 67890")
    mock_console_print.assert_any_call("  [bold]Description:[/] Another sequence")
    mock_console_print.assert_any_call("  [bold]Sequence Length:[/] 7 bp")


    # Verify Entrez calls
    mock_entrez.esearch.assert_called_with(db="nucleotide", term="CRISPR", retmax=5)
    
    # Assert Entrez.read was called *once* with the esearch handle.
    mock_entrez.read.assert_called_once_with(mock_esearch_handle)
    
    mock_entrez.efetch.assert_called_with(
        db="nucleotide", id=["12345", "67890"], rettype="gb", retmode="text"
    )

    # Assert the efetch handle's read() method was called once.
    mock_efetch_handle.read.assert_called_once()
    
    # Assert SeqIO.parse was called once
    mock_seqio_parse.assert_called_once()


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