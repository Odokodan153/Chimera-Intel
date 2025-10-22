from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.bioint import bioint_app

runner = CliRunner()


@patch("chimera_intel.core.bioint.search_genbank")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_success(mock_console_print, mock_search_genbank):
    """Tests the command when sequences are found."""
    # Create fake records to be returned by the mocked function
    mock_record_1 = MagicMock()
    mock_record_1.id = "12345"
    mock_record_1.description = "Synthetic sequence 1"
    mock_record_1.seq = "ATGC"

    mock_record_2 = MagicMock()
    mock_record_2.id = "67890"
    mock_record_2.description = "Synthetic sequence 2"
    mock_record_2.seq = "CGTA"

    # Set the return value for the mocked search_genbank function
    mock_search_genbank.return_value = [mock_record_1, mock_record_2]

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

    # Check that the command exited successfully
    assert result.exit_code == 0, result.stdout

    # Verify the mock search function was called correctly
    # FIXED: Changed 'target' to 'query' to match the search_genbank function definition
    mock_search_genbank.assert_called_with(query="CRISPR", email="test@example.com")

    # Check that console.print was called with the expected startup message
    mock_console_print.assert_any_call(
        "Monitoring [bold cyan]GenBank[/bold cyan] for target: '[yellow]CRISPR[/yellow]'"
    )
    # Check that console.print was called with the expected results
    mock_console_print.assert_any_call(
        "\n--- [bold green]Found 2 Matching Sequences[/bold green] ---"
    )
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 12345")
    mock_console_print.assert_any_call("  [bold]Description:[/] Synthetic sequence 1")
    mock_console_print.assert_any_call("  [bold]Sequence Length:[/] 4 bp")
    mock_console_print.assert_any_call("\n> [bold]Accession ID:[/] 67890")


@patch("chimera_intel.core.bioint.search_genbank")
@patch("chimera_intel.core.bioint.console.print", new_callable=MagicMock)
def test_monitor_sequences_no_results(mock_console_print, mock_search_genbank):
    """Tests the command when no sequences are found."""
    # No results returned
    mock_search_genbank.return_value = []

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

    # The command should still exit with 0, as it's handled
    assert result.exit_code == 0, result.stdout

    # Verify the mock search function was called
    # FIXED: Changed 'target' to 'query' to match the search_genbank function definition
    mock_search_genbank.assert_called_with(
        query="unknown_sequence", email="test@example.com"
    )

    # Check that the "no results" message was printed
    mock_console_print.assert_any_call("[yellow]No matching sequences found.[/yellow]")