"""
Module for Topic Clustering.

Analyzes a collection of documents to automatically group them into
emerging themes or topics and names them.
"""

import typer
import logging
import json
from typing import List, Optional, Dict
from chimera_intel.core.schemas import TopicClusteringResult, TopicCluster
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
topic_clusterer_app = typer.Typer()


def run_topic_clustering(
    documents: List[Dict[str, str]]
) -> TopicClusteringResult:
    """
    Uses an LLM to perform topic clustering on a list of documents.

    Args:
        documents (List[Dict[str, str]]): A list of dictionaries, each with
                                           at least a "content" key.

    Returns:
        TopicClusteringResult: A Pydantic model with the cluster results.
    """
    logger.info(f"Running topic clustering for {len(documents)} documents.")

    if not documents:
        return TopicClusteringResult(
            total_documents_analyzed=0,
            total_clusters_found=0,
            clusters=[],
            error="No documents provided.",
        )

    # Create snippets. Using an index is crucial for mapping results.
    doc_snippets = []
    for i, doc in enumerate(documents):
        content = doc.get("content", "")
        if content:
            hint = content[:150] + "..." if len(content) > 150 else content
            doc_snippets.append(f"Doc {i}: \"{hint}\"")

    if not doc_snippets:
        return TopicClusteringResult(
            total_documents_analyzed=len(documents),
            total_clusters_found=0,
            clusters=[],
            error="No valid content found in documents.",
        )

    all_snippets_str = "\n".join(doc_snippets)

    prompt = f"""
You are an AI data analyst. I have a list of documents.
Your task is to identify emerging themes and cluster these documents by topic.

Instructions:
1.  Read all the document snippets provided.
2.  Group them into 2-5 distinct topic clusters.
3.  Assign a short, descriptive name (2-4 words) for each cluster (e.g., "AI Regulation").
4.  List the document indices (e.g., `Doc 0`, `Doc 1`) that belong to each cluster.
5.  Documents that don't fit any clear topic should be ignored.
6.  Return *only* a JSON object in the following format:
    `{{"clusters": [{{"cluster_name": "...", "document_ids": [...]}}]}}`

Document Snippets:
{all_snippets_str}
"""

    llm_response = gemini_client.generate_response(prompt)
    if not llm_response:
        logger.warning("LLM call for clustering returned empty.")
        return TopicClusteringResult(
            total_documents_analyzed=len(documents),
            total_clusters_found=0,
            clusters=[],
            error="LLM call returned no response.",
        )

    try:
        response_json = json.loads(llm_response)
        parsed_clusters = response_json.get("clusters", [])

        final_clusters: List[TopicCluster] = []
        clustered_indices = set()
        
        for i, cluster_data in enumerate(parsed_clusters):
            doc_indices = cluster_data.get("document_ids", [])
            doc_hints = []
            valid_indices = []
            
            for idx in doc_indices:
                if 0 <= idx < len(documents):
                    doc_content = documents[idx].get("content", "")
                    hint = doc_content[:75] + "..." if len(doc_content) > 75 else doc_content
                    doc_hints.append(hint)
                    valid_indices.append(idx)
                    clustered_indices.add(idx)
                
            if valid_indices:
                final_clusters.append(
                    TopicCluster(
                        cluster_id=i,
                        cluster_name=cluster_data.get("cluster_name", "Unnamed Cluster"),
                        document_indices=valid_indices,
                        document_hints=doc_hints,
                        document_count=len(valid_indices),
                    )
                )

        unclustered_count = len(documents) - len(clustered_indices)

        return TopicClusteringResult(
            total_documents_analyzed=len(documents),
            total_clusters_found=len(final_clusters),
            clusters=final_clusters,
            unclustered_documents=unclustered_count,
        )

    except (json.JSONDecodeError, TypeError, ValueError) as e:
        logger.error(f"Failed to parse LLM clustering response: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")
        return TopicClusteringResult(
            total_documents_analyzed=len(documents),
            total_clusters_found=0,
            clusters=[],
            error=f"Failed to parse LLM response: {e}",
        )


@topic_clusterer_app.command("run")
def run_topic_clustering_cli(
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON file containing a list of objects, "
             "each with a 'content' key.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
    target: Optional[str] = typer.Argument(
        "default",
        help="The project target to associate this scan with. Defaults to 'default'.",
    ),
):
    """
    Analyzes documents to find and name emerging topic clusters.
    """
    target_name = resolve_target(target, required_assets=[])

    try:
        with open(input_file, "r") as f:
            documents = json.load(f)
        if not isinstance(documents, list):
            raise ValueError("Input file must contain a JSON list.")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}': {e}")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Analyzing topic clusters for {target_name}...[/bold cyan]"
    ):
        results_model = run_topic_clustering(documents)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="topic_clustering", data=results_dict
    )