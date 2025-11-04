"""
Data Ingestion, Storage, and Orchestration Pipeline.

This module provides an asynchronous pipeline (using Celery) to:
1.  Scrape static (requests) and dynamic (playwright) web pages.
2.  Store raw ingested files (e.g., HTML) in an S3 bucket.
3.  Log structured metadata (e.g., URL, title, S3 key) in PostgreSQL.
4.  Index document content for full-text search in Elasticsearch.

NOTE ON DEPENDENCIES:
This module requires:
pip install celery[redis] playwright beautifulsoup4 boto3 elasticsearch-py
You must also run 'playwright install' to install browser binaries.

NOTE ON CONFIG:
This module assumes config (API keys, DB URIs) is loaded from environment
variables or a central config (like .env). E.g.,
- CELERY_BROKER_URL="redis://localhost:6379/0"
- CELERY_RESULT_BACKEND="redis://localhost:6379/0"
- S3_BUCKET="your-chimera-raw-data-bucket"
- AWS_ACCESS_KEY_ID="YOUR_AWS_KEY"
- AWS_SECRET_ACCESS_KEY="YOUR_AWS_SECRET"
- POSTGRES_DSN="postgresql://user:pass@localhost:5432/chimera"
- ELASTICSEARCH_URL="http://localhost:9200"
"""

import typer
import os
import logging
import json
import hashlib
import pathlib  # <-- This was the missing import
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from celery import Celery
from chimera_intel.core.models import IngestionResult
from bs4 import BeautifulSoup
import requests
from playwright.async_api import async_playwright
import boto3
from botocore.exceptions import NoCredentialsError
from elasticsearch import Elasticsearch
import psycopg2
from psycopg2.extras import Json

from rich.console import Console
from .utils import save_or_print_results

# --- Setup ---
logger = logging.getLogger(__name__)
console = Console()
pipeline_app = typer.Typer(
    name="pipeline",
    help="Data ingestion, storage, and indexing pipeline.",
)

# --- Configuration (Loaded from Environment) ---
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
S3_BUCKET = os.environ.get("S3_BUCKET", "chimera-intel-pipeline")
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "postgresql://user:pass@localhost:5432/chimera")
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")

# --- Celery Orchestration Setup ---

try:
    celery_app = Celery(
        "chimera_pipeline",
        broker=CELERY_BROKER_URL,
        backend=CELERY_RESULT_BACKEND
    )
    celery_app.conf.update(
        task_track_started=True,
        broker_connection_retry_on_startup=True
    )
except Exception as e:
    logger.error(f"Could not initialize Celery. Ensure Redis is running. Error: {e}")
    console.print(f"[bold red]Error:[/bold red] Could not initialize Celery. Ensure Redis is running at [cyan]{CELERY_BROKER_URL}[/cyan]")
    celery_app = None


# --- 1. Scraping / Ingestion ---

def scrape_static_page(url: str) -> Tuple[str, str]:
    """Scrapes a static HTML page using requests."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    content = response.text
    soup = BeautifulSoup(content, "html.parser")
    title = soup.title.string if soup.title else "No Title Found"
    return content, title

async def ascrape_dynamic_page(url: str) -> Tuple[str, str]:
    """Scrapes a dynamic (JS-rendered) page using playwright."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle")
        content = await page.content()
        title = await page.title()
        await browser.close()
        return content, title

# --- 2. Storage & Indexing ---

def upload_to_s3(data_bytes: bytes, key: str) -> str:
    """Uploads data bytes to the configured S3 bucket."""
    try:
        s3 = boto3.client("s3")
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=data_bytes)
        return key
    except NoCredentialsError:
        logger.error("S3 credentials not found.")
        raise
    except Exception as e:
        logger.error(f"Error uploading to S3: {e}")
        raise

def log_to_postgres(metadata: Dict[str, Any]) -> int:
    """Logs ingestion metadata to the PostgreSQL database."""
    # NOTE: In a real app, use the pooled connection from database.py
    # This is a simplified example.
    conn = psycopg2.connect(POSTGRES_DSN)
    cur = conn.cursor()
    
    # Ensure table exists (simplified)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ingestion_log (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            s3_key TEXT NOT NULL,
            content_hash_sha256 TEXT,
            title TEXT,
            ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB
        );
    """)
    
    insert_query = """
        INSERT INTO ingestion_log (url, s3_key, content_hash_sha256, title, metadata)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
    """
    cur.execute(
        insert_query,
        (
            metadata.get("url"),
            metadata.get("s3_key"),
            metadata.get("content_hash"),
            metadata.get("title"),
            Json(metadata.get("extra_meta", {})),
        ),
    )
    postgres_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return postgres_id

def index_in_elasticsearch(doc_id: str, document: Dict[str, Any], index: str = "chimera_documents"):
    """Indexes a document in Elasticsearch."""
    try:
        es = Elasticsearch(ELASTICSEARCH_URL)
        if not es.ping():
            raise ConnectionError("Elasticsearch is not reachable.")
        
        response = es.index(index=index, id=doc_id, document=document)
        return response["_id"]
    except Exception as e:
        logger.error(f"Error indexing in Elasticsearch: {e}")
        raise

# --- 3. Orchestration (Celery Task) ---

@celery_app.task(name="pipeline.ingest_url")
def ingest_url_task(url: str, is_dynamic: bool = False) -> Dict[str, Any]:
    """
    The main Celery task for the full ingestion pipeline.
    """
    start_time = datetime.now(timezone.utc)
    logger.info(f"Starting ingestion for URL: {url}")
    
    try:
        # 1. Scraping
        if is_dynamic:
            # Note: Celery tasks are not async by default.
            # Running async in sync context.
            import asyncio
            content, title = asyncio.run(ascrape_dynamic_page(url))
        else:
            content, title = scrape_static_page(url)
        
        content_bytes = content.encode("utf-8")
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        
        # 2. Storage
        s3_key = f"raw_pages/{content_hash}.html"
        upload_to_s3(content_bytes, s3_key)
        
        # 3. Metadata Logging (Postgres)
        metadata = {
            "url": url,
            "s3_key": s3_key,
            "content_hash": content_hash,
            "title": title,
            "ingested_at": start_time.isoformat(),
            "extra_meta": {
                "scraper": "playwright" if is_dynamic else "requests"
            }
        }
        pg_id = log_to_postgres(metadata)
        
        # 4. Indexing (Elasticsearch)
        soup = BeautifulSoup(content, "html.parser")
        page_text = soup.get_text(separator=" ", strip=True)
        
        es_document = {
            "url": url,
            "title": title,
            "content": page_text,
            "ingested_at": start_time,
            "s3_key": s3_key,
            "postgres_id": pg_id
        }
        es_id = index_in_elasticsearch(doc_id=content_hash, document=es_document)
        
        result = IngestionResult(
            url=url,
            status="SUCCESS",
            content_hash=content_hash,
            s3_key=s3_key,
            postgres_id=pg_id,
            elastic_id=es_id,
            title=title
        )
        
    except Exception as e:
        logger.error(f"Pipeline failed for {url}: {e}")
        result = IngestionResult(
            url=url,
            status="FAILED",
            content_hash="",
            s3_key="",
            postgres_id=-1,
            elastic_id="",
            error=str(e)
        )
        
    return result.model_dump(exclude_none=True)

# --- 4. CLI ---

@pipeline_app.command(
    "ingest", 
    help="Trigger the ingestion pipeline for a URL."
)
def cli_ingest_url(
    url: str = typer.Argument(..., help="The URL to ingest."),
    dynamic: bool = typer.Option(
        False, "--dynamic", "-d", help="Use dynamic scraping (Playwright) for JS-heavy sites."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save task result to a JSON file."
    ),
):
    """
    Submits a new URL to the data ingestion pipeline (Celery).
    """
    if not celery_app:
        console.print("[bold red]Error:[/bold red] Celery is not initialized. Cannot submit task.")
        raise typer.Exit(code=1)
        
    console.print(f"Submitting ingestion task for: [bold cyan]{url}[/bold cyan] (Dynamic: {dynamic})")
    
    try:
        # .delay() submits the task to the Celery queue
        task = ingest_url_task.delay(url=url, is_dynamic=dynamic)
        
        console.print(f"Task submitted with ID: [bold green]{task.id}[/bold green]")
        console.print("Waiting for result (this may take a moment)...")
        
        # .get() waits for the task to finish and retrieves the result
        result_data = task.get(timeout=120) # 2 minute timeout
        
        console.print("\n--- [bold green]Ingestion Complete[/bold green] ---")
        save_or_print_results(result_data, output_file)
        
        if result_data.get("status") == "FAILED":
             console.print(f"\n[bold red]Error during ingestion:[/bold red] {result_data.get('error')}")

    except Exception as e:
        console.print(f"\n[bold red]An error occurred while submitting or retrieving the task:[/bold red] {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    # This allows running the module directly, but it's meant
    # to be imported by the main chimera CLI.
    # To run the worker, use: celery -A chimera_intel.core.data_pipeline.celery_app worker --loglevel=info
    pipeline_app()