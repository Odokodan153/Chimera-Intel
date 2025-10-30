from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@patch("chimera_intel.core.bioint.SeqIO.parse")
@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(mock_console_print, mock_entrez, mock_seqio_parse):
    """(Original Test)"""
    # Mock esearch and efetch
    mock_esearch_handle = MagicMock()
    mock_efetch_handle = MagicMock()

    mock_entrez.esearch.return_value = mock_esearch_handle
    mock_entrez.efetch.return_value = mock_efetch_handle
    mock_entrez.read.return_value = {"IdList": ["12345", "67890"]}
    mock_efetch_handle.read.return_value = "Mocked GenBank text data"

    # Configure SeqIO.parse to return mock records
    mock_record_1 = MagicMock()
    mock_record_1.id = "12345"
    mock_record_1.description = "Synthetic construct"
    mock_record_1.seq = "ATCG"

    mock_record_2 = MagicMock()
    mock_record_2.id = "67890"
    mock_record_2.description = "Another sequence"
    mock_record_2.seq = "GATTACA"

    mock_seqio_parse.return_value = [mock_record_1, mock_record_2]

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
    mock_console_print.assert_any_call(
        "Monitoring [bold cyan]GenBank[/bold cyan] for target: '[yellow]CRISPR[/yellow]'"
    )
    mock_console_print.assert_any_call(
        "\n--- [bold green]Found 2 Matching Sequences[/bold green] ---"
    )
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 12345")


@patch("chimera_intel.core.bioint.Entrez")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_no_results(mock_console_print, mock_entrez):
    """(Original Test)"""
    # No results returned
    mock_esearch_handle = MagicMock()
    mock_entrez.esearch.return_value = mock_esearch_handle
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


# --- Extended Test ---
@patch("chimera_intel.core.bioint.search_genbank")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_unsupported_db(mock_console_print, mock_search):
    """
    Tests the CLI command when an unsupported database is provided.
    This covers the 'if db.lower() != "genbank":' block.
    """
    # CLI invocation
    result = runner.invoke(
        bioint_app,
        [
            "--target",
            "CRISPR",
            "--email",
            "test@example.com",
            "--db",
            "NotGenBank",
        ],
    )

    # Assert failure
    assert result.exit_code == 1, result.stdout
    # Check that the correct error message was printed
    mock_console_print.assert_any_call(
        "[bold red]Error:[/bold red] Only 'GenBank' is supported at this time."
    )
    # Ensure search was not called
    mock_search.assert_not_called()


# --- Extended Test ---
@patch("chimera_intel.core.bioint.search_genbank")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_search_exception(mock_console_print, mock_search):
    """
    Tests the 'except Exception as e' block in the CLI command.
    """
    # Arrange
    mock_search.side_effect = Exception("NCBI is down")

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

    # Assert failure
    assert result.exit_code == 1, result.stdout
    # Check that the exception was caught and printed
    mock_console_print.assert_any_call(
        "[bold red]An error occurred during BIOINT monitoring:[/bold red] NCBI is down"
    )
