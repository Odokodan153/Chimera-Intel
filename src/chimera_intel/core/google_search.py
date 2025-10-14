# src/chimera_intel/core/google_search.py

from googlesearch import search as google_search_func
from typing import List

def search(queries: List[str], num_results: int = 10) -> List[str]:
    """
    Performs a simple Google search for multiple queries and returns a list of URLs.

    Args:
        queries (List[str]): A list of search queries.
        num_results (int): The number of results to return for each query.

    Returns:
        List[str]: A list of result URLs.
    """
    all_results = []
    for query in queries:
        try:
            results = list(google_search_func(query, num_results=num_results))
            all_results.extend(results)
        except Exception as e:
            print(f"An error occurred during Google search for query '{query}': {e}")
    return all_results