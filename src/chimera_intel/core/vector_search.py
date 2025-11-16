"""
Module for Vector Embeddings and Similarity Search (CLIP/FAISS).

Provides tools to:
1.  Generate CLIP vector embeddings for images.
2.  Build a searchable FAISS index from a directory of images.
3.  Perform local reverse image search (nearest neighbor) against a FAISS index.

NOTE ON DEPENDENCIES:
This module requires:
pip install faiss-cpu sentence-transformers torch
"""

import typer
import pathlib
import json
import numpy as np
from PIL import Image
from typing import Optional
from rich.console import Console
from rich.table import Table
from .schemas import EmbeddingResult, SearchResult, SearchMatch
try:
    import faiss
    from sentence_transformers import SentenceTransformer
except ImportError:
    faiss = None
    pass
from .utils import save_or_print_results

console = Console()
vector_app = typer.Typer(
    name="vector-search",
    help="Image similarity search using CLIP embeddings and FAISS.",
)

# Global model cache
MODEL_CACHE = {}
MODEL_NAME = "clip-ViT-B-32"

def _check_imports():
    """Checks if FAISS and SentenceTransformers are installed."""
    # [FIX 2] Check if 'SentenceTransformer' is in globals
    if faiss is None or "SentenceTransformer" not in globals():
        console.print("[bold red]Error: Missing dependencies for vector search.[/bold red]")
        console.print("Please run: [cyan]pip install faiss-cpu sentence-transformers[/cyan]")
        raise typer.Exit(code=1)

def _get_model(model_name: str = MODEL_NAME) -> "SentenceTransformer":
    """Loads and caches the SentenceTransformer (CLIP) model."""
    _check_imports()
    if model_name not in MODEL_CACHE:
        console.print(f"Loading '{model_name}' model into memory...")
        try:
            # This is now safe because _check_imports() passed
            MODEL_CACHE[model_name] = SentenceTransformer(model_name)
            console.print("[bold green]Model loaded successfully.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error loading model:[/bold red] {e}")
            raise typer.Exit(code=1)
    return MODEL_CACHE[model_name]

def get_image_embedding(image_path: pathlib.Path) -> np.ndarray:
    """
    Generates a vector embedding for a single image using CLIP.
    """
    model = _get_model()
    try:
        img = Image.open(image_path).convert("RGB")
        # The encode method for CLIP models takes a PIL Image directly
        embedding = model.encode([img], show_progress_bar=False)
        return embedding[0]
    except Exception as e:
        console.print(f"[bold red]Error generating embedding for {image_path.name}:[/bold red] {e}")
        raise

# --- CLI Commands ---

@vector_app.command("embed", help="Generate a CLIP vector embedding for a single image.")
def cli_embed_image(
    image_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the image file."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save embedding to a JSON file."
    ),
):
    """
    Generates and displays the CLIP vector embedding for a single image.
    """
    try:
        embedding = get_image_embedding(image_path)
        result = EmbeddingResult(
            file_path=str(image_path),
            embedding=embedding.tolist()
        )
        save_or_print_results(result.model_dump(exclude_none=True), output_file)
    except Exception as e:
        console.print(f"[bold red]Failed to process image:[/bold red] {e}")
        raise typer.Exit(code=1)

@vector_app.command("build-index", help="Build a FAISS index from a directory of images.")
def cli_build_index(
    image_directory: pathlib.Path = typer.Argument(
        ..., exists=True, dir_okay=True, file_okay=False,
        help="Directory containing images to index."
    ),
    index_prefix: str = typer.Option(
        "faiss_index",
        "--prefix",
        "-p",
        help="Prefix for the output files (e.g., 'faiss_index.index', 'faiss_index.json').",
    ),
):
    """
    Walks a directory, generates CLIP embeddings for all images,
    and saves a FAISS index and a mapping file.
    """
    _check_imports()
    model = _get_model()
    
    image_paths = sorted([
        p for p in image_directory.rglob("*") 
        if p.suffix.lower() in {".jpg", ".jpeg", ".png", ".bmp"}
    ])
    
    if not image_paths:
        console.print(f"[bold red]Error:[/bold red] No images found in '{image_directory}'.")
        raise typer.Exit(code=1)

    console.print(f"Found {len(image_paths)} images. Generating embeddings...")
    
    # Batch encode images for efficiency
    pil_images = [Image.open(p).convert("RGB") for p in image_paths]
    embeddings = model.encode(pil_images, show_progress_bar=True, convert_to_numpy=True)
    
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)  # Using L2 (Euclidean) distance
    index.add(embeddings)
    
    console.print(f"Index built with {index.ntotal} vectors of dimension {dimension}.")
    
    # Save the index
    index_file = f"{index_prefix}.index"
    faiss.write_index(index, index_file)
    console.print(f"FAISS index saved to: [cyan]{index_file}[/cyan]")
    
    # Save the mapping (Index ID -> File Path)
    mapping = {i: str(image_paths[i]) for i in range(len(image_paths))}
    map_file = f"{index_prefix}.json"
    with open(map_file, "w") as f:
        json.dump(mapping, f, indent=2)
    console.print(f"Index mapping saved to: [cyan]{map_file}[/cyan]")

@vector_app.command("search", help="Search the FAISS index for similar images.")
def cli_search_index(
    query_image: pathlib.Path = typer.Argument(
        ..., exists=True, help="The image to find matches for."
    ),
    index_prefix: str = typer.Option(
        "faiss_index",
        "--prefix",
        "-p",
        help="Prefix of the index files to search (e.g., 'faiss_index').",
    ),
    top_k: int = typer.Option(
        5, "--top-k", "-k", help="Number of similar images to return."
    ),
):
    """
    Generates an embedding for the query image and finds the Top-K
    nearest neighbors in the specified FAISS index.
    """
    _check_imports()
    
    index_file = f"{index_prefix}.index"
    map_file = f"{index_prefix}.json"
    
    # 1. Load Index and Map
    if not pathlib.Path(index_file).exists() or not pathlib.Path(map_file).exists():
        console.print(f"[bold red]Error:[/bold red] Index files not found.")
        console.print(f"Expected: [cyan]{index_file}[/cyan] and [cyan]{map_file}[/cyan]")
        console.print("Run 'build-index' first.")
        raise typer.Exit(code=1)

    try:
        index = faiss.read_index(index_file)
        with open(map_file, "r") as f:
            mapping = {int(k): v for k, v in json.load(f).items()} # Ensure keys are integers
    except Exception as e:
        console.print(f"[bold red]Error loading index files:[/bold red] {e}")
        raise typer.Exit(code=1)

    console.print(f"Loaded index with {index.ntotal} vectors.")
    
    # 2. Generate Query Embedding
    console.print(f"Generating embedding for query image: [cyan]{query_image.name}[/cyan]")
    try:
        query_vector = get_image_embedding(query_image)
        query_vector = np.expand_dims(query_vector, axis=0) # Must be 2D array for search
    except Exception as e:
        console.print(f"[bold red]Failed to process query image:[/bold red] {e}")
        raise typer.Exit(code=1)
        
    # 3. Search Index
    # D = distances, I = indices
    distances, indices = index.search(query_vector, top_k)
    
    results = SearchResult(query_path=str(query_image), matches=[])
    
    table = Table(title="Vector Search Results")
    table.add_column("Rank", style="magenta")
    table.add_column("Match Path", style="cyan")
    table.add_column("Distance (L2)", style="yellow")
    
    for i in range(top_k):
        match_id = indices[0][i]
        match_dist = distances[0][i]
        match_path = mapping.get(match_id, "Error: Unknown Index")
        
        results.matches.append(SearchMatch(match_path=match_path, distance=match_dist))
        table.add_row(str(i+1), match_path, f"{match_dist:.4f}")

    console.print(table)


if __name__ == "__main__":
    vector_app()