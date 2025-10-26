import pytest
from unittest.mock import patch, MagicMock, ANY
from typer.testing import CliRunner

# Import the Typer app to be tested
from src.chimera_intel.core.graph_cli import graph_app

# Create a test runner
runner = CliRunner()


@pytest.fixture
def mock_db():
    """Fixture to mock the graph_db_instance."""
    # We patch the instance inside the module where it's *used*
    with patch("src.chimera_intel.core.graph_cli.graph_db_instance") as mock_db:
        yield mock_db


# --- Tests for "query" command ---

def test_run_cypher_query_success_with_results(mock_db):
    """Test the 'query' command with a successful query that returns results."""
    # Mock the return value of execute_query
    mock_db.execute_query.return_value = [
        {"node": "example.com", "ip": "1.2.3.4"},
        {"node": "test.com", "ip": "5.6.7.8"},
    ]

    query = "MATCH (n) RETURN n.name as node, n.ip as ip"
    result = runner.invoke(graph_app, ["query", query])

    assert result.exit_code == 0
    assert "Query executed successfully" in result.stdout
    assert "example.com" in result.stdout
    assert "5.6.7.8" in result.stdout
    mock_db.execute_query.assert_called_with(query)


def test_run_cypher_query_success_no_results(mock_db):
    """Test the 'query' command with a successful query that returns no results."""
    mock_db.execute_query.return_value = []

    query = "MATCH (n:NonExistentLabel) RETURN n"
    result = runner.invoke(graph_app, ["query", query])

    assert result.exit_code == 0
    assert "Query executed successfully" in result.stdout
    # Check that no table data is printed
    assert "node" not in result.stdout


def test_run_cypher_query_db_exception(mock_db):
    """Test the 'query' command when the database raises an exception."""
    mock_db.execute_query.side_effect = Exception("Invalid Cypher syntax")

    query = "MATCH (n) RETURN n"
    result = runner.invoke(graph_app, ["query", query])

    assert result.exit_code == 0  # Typer CLI handles exceptions gracefully
    assert "Error executing query" in result.stdout
    assert "Invalid Cypher syntax" in result.stdout


# --- Tests for "find-path" command ---

def test_find_shortest_path_success(mock_db):
    """Test 'find-path' when a path is successfully found."""
    # Mocking a path object is complex, so we'll mock the components
    mock_node_start = MagicMock()
    mock_node_start.get.return_value = "example.com"
    mock_node_end = MagicMock()
    mock_node_end.get.return_value = "1.2.3.4"

    mock_rel = MagicMock()
    mock_rel.type = "RESOLVES_TO"

    mock_path = MagicMock()
    mock_path.nodes = [mock_node_start, mock_node_end]
    mock_path.relationships = [mock_rel]

    mock_db.execute_query.return_value = [{"p": mock_path}]

    result = runner.invoke(
        graph_app, ["find-path", "--from", "Domain:example.com", "--to", "IP:1.2.3.4"]
    )

    assert result.exit_code == 0
    assert "Path found!" in result.stdout
    assert "(example.com)-[RESOLVES_TO]->(1.2.3.4)" in result.stdout
    mock_db.execute_query.assert_called_with(
        ANY, {"start_name": "example.com", "end_name": "1.2.3.4"}
    )


def test_find_shortest_path_no_path_found(mock_db):
    """Test 'find-path' when no path is found."""
    mock_db.execute_query.return_value = []

    result = runner.invoke(
        graph_app, ["find-path", "--from", "Domain:a.com", "--to", "IP:b.com"]
    )

    assert result.exit_code == 0
    assert "No path found" in result.stdout


def test_find_shortest_path_invalid_format(mock_db):
    """Test 'find-path' with incorrectly formatted node strings."""
    result = runner.invoke(
        graph_app, ["find-path", "--from", "Domainexample.com", "--to", "IP:1.2.3.4"]
    )

    assert result.exit_code == 0
    assert "Error: Node format must be 'Label:Name'" in result.stdout
    mock_db.execute_query.assert_not_called()


def test_find_shortest_path_db_exception(mock_db):
    """Test 'find-path' when the database query fails."""
    mock_db.execute_query.side_effect = Exception("DB connection lost")

    result = runner.invoke(
        graph_app, ["find-path", "--from", "Domain:example.com", "--to", "IP:1.2.3.4"]
    )

    assert result.exit_code == 0
    assert "An error occurred" in result.stdout
    assert "DB connection lost" in result.stdout