from unittest.mock import patch

# Import the function to be tested
from src.chimera_intel.core.google_search import search


@patch("src.chimera_intel.core.google_search.google_search_func")
def test_search_success(mock_google_search):
    """Test a successful search with multiple queries."""
    # Mock the return value of the imported search function
    mock_google_search.side_effect = [
        ["http://result1.com", "http://result2.com"],  # Results for "query1"
        ["http://result3.com"],  # Results for "query2"
    ]

    queries = ["query1", "query2"]
    results = search(queries, num_results=5)

    assert results == ["http://result1.com", "http://result2.com", "http://result3.com"]
    # Check that it was called correctly
    mock_google_search.assert_any_call("query1", num_results=5)
    mock_google_search.assert_any_call("query2", num_results=5)


@patch("src.chimera_intel.core.google_search.google_search_func")
@patch("builtins.print")  # Mock the print function to capture output
def test_search_exception(mock_print, mock_google_search):
    """Test the search function when the external library raises an exception."""
    # Mock the search function to raise an exception for the first query
    mock_google_search.side_effect = [
        Exception("Search Error"),
        ["http://result3.com"],  # Subsequent queries should still work
    ]

    queries = ["failing_query", "working_query"]
    results = search(queries, num_results=10)

    # The function should catch the exception and continue
    assert results == ["http://result3.com"]

    # Check that the error was printed
    mock_print.assert_called_with(
        "An error occurred during Google search for query 'failing_query': Search Error"
    )
