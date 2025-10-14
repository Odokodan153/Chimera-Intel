# src/chimera_intel/core/google_search.py

from googlesearch import search as google_search_func
from typing import List

def search(query: str, num_results: int = 10) -> List[str]:
    """
    Performs a simple Google search and returns a list of URLs.

    Args:
        query (str): The search query.
        num_results (int): The number of results to return.

    Returns:
        List[str]: A list of result URLs.
    """
    try:
        results = list(google_search_func(query, num_results=num_results))
        return results
    except Exception as e:
        print(f"An error occurred during Google search: {e}")
        return []