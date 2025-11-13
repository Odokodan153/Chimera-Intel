"""
IMINT Ingestion Pipeline (Production Version)

This module provides the core functionality for ingesting, processing,
and enriching image data from various open-web, social, and internal sources.

It handles:
1.  Fetching images from URLs.
2.  Connecting to various source types (social media, reverse search, etc.).
3.  Normalizing image metadata.
4.  Storing the raw image (e.g., in S3).
5.  Calculating features for indexing (pHash, CLIP embeddings).
6.  Enriching the image (OCR, face/logo detection, EXIF).
7.  Linking the image to entities in the ARG (graph database).

NOTE ON DEPENDENCIES:
This module requires:
pip install boto3 pillow imagehash opencv-python-headless easyocr \
            playwright tineye-api google-cloud-vision google-api-python-client \
            tweepy transformers torch
            
You also need to run 'playwright install'
"""

import typer
import os
import logging
import requests
import hashlib
import imagehash
import uuid
import boto3
import cv2
import easyocr
import torch
from io import BytesIO
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from pydantic import HttpUrl
from PIL import Image, ExifTags
from botocore.exceptions import NoCredentialsError, ClientError
from playwright.async_api import async_playwright
from tineye_api import TinEyeAPIRequest
from google.cloud import vision
from googleapiclient.discovery import build as google_api_build
from tweepy import Client as TweepyClient
from transformers import CLIPProcessor, CLIPModel

# Assuming schemas are in .schemas and other modules are siblings
from .schemas import IngestedImageRecord, ImageSourceType, ImageFeatures, ImageEnrichment, ExifData, Node, Edge
from .utils import console, get_db_connection, save_or_print_results
from .graph_db import get_graph_driver

# --- Setup ---
logger = logging.getLogger(__name__)
imint_ingestion_app = typer.Typer(
    name="ingest",
    help="Image (IMINT) ingestion pipeline.",
)

# --- Configuration (from environment or config.yaml) ---
S3_BUCKET = os.environ.get("S3_BUCKET", "chimera-intel-imint-storage")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

# API Keys
TINEYE_API_KEY = os.environ.get("TINEYE_API_KEY")
TWITTER_BEARER_TOKEN = os.environ.get("TWITTER_BEARER_TOKEN")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY") # For Google Custom Search
GOOGLE_CUSTOM_SEARCH_CX = os.environ.get("GOOGLE_CUSTOM_SEARCH_CX") # For Google Custom Search
# GOOGLE_APPLICATION_CREDENTIALS must be set in env for Google Vision

# --- Global Clients (initialized once) ---

def_model = "openai/clip-vit-base-patch32"

# Initialize EasyOCR
try:
    ocr_reader = easyocr.Reader(['en'])
except Exception as e:
    logger.warning(f"Could not initialize EasyOCR reader. OCR will be skipped. Error: {e}")
    ocr_reader = None

# Initialize OpenCV Face Classifier
FACE_CASCADE_PATH = os.environ.get("FACE_CASCADE_PATH", "src/chimera_intel/assets/haarcascade_frontalface_default.xml")
try:
    if not os.path.exists(FACE_CASCADE_PATH):
        raise IOError(f"Face cascade file not found at {FACE_CASCADE_PATH}")
    face_cascade = cv2.CascadeClassifier(FACE_CASCADE_PATH)
    if face_cascade.empty():
        raise IOError(f"Could not load face cascade XML from {FACE_CASCADE_PATH}")
except Exception as e:
    logger.warning(f"Could not initialize OpenCV face detector. Face detection will be skipped. Error: {e}")
    face_cascade = None

# Initialize Boto3 S3 Client
try:
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    s3_client.head_bucket(Bucket=S3_BUCKET)
    logger.info(f"Successfully connected to S3 bucket: {S3_BUCKET}")
except (NoCredentialsError, ClientError) as e:
    logger.warning(f"S3 credentials not found or bucket error. Storage will fail. Error: {e}")
    s3_client = None

# Initialize Google Vision Client
try:
    gcp_vision_client = vision.ImageAnnotatorClient()
    logger.info("Google Cloud Vision client initialized.")
except Exception as e:
    logger.warning(f"Google Cloud Vision client failed to initialize. Set GOOGLE_APPLICATION_CREDENTIALS. Error: {e}")
    gcp_vision_client = None

# Initialize CLIP Model (Transformers)
try:
    clip_model = CLIPModel.from_pretrained(def_model)
    clip_processor = CLIPProcessor.from_pretrained(def_model)
    logger.info(f"CLIP model '{def_model}' loaded successfully.")
except Exception as e:
    logger.warning(f"Could not load CLIP model. Embeddings will be skipped. Error: {e}")
    clip_model = None
    clip_processor = None

# --- 1. Connectors (Data Source Fetching) ---

def fetch_images_from_google(query: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Fetches images using the Google Custom Search JSON API."""
    console.print(f"Connecting to [bold yellow]Google Custom Search API[/bold yellow] for query: '{query}'")
    if not GOOGLE_API_KEY or not GOOGLE_CUSTOM_SEARCH_CX:
        logger.error("GOOGLE_API_KEY or GOOGLE_CUSTOM_SEARCH_CX not set. Skipping Google search.")
        return []

    try:
        service = google_api_build("customsearch", "v1", developerKey=GOOGLE_API_KEY)
        response = service.cse().list(
            q=query,
            cx=GOOGLE_CUSTOM_SEARCH_CX,
            searchType="image",
            num=max_results,
            safe="off"
        ).execute()
        
        results = []
        for item in response.get("items", []):
            results.append({
                "source_url": item["link"],
                "source_context_url": item["image"]["contextLink"],
                "source_type": ImageSourceType.GOOGLE_IMAGES,
                "metadata": {"title": item.get("title")}
            })
        return results
    except Exception as e:
        logger.error(f"Google Custom Search API failed: {e}")
        return []


def fetch_images_from_twitter(query: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Fetches images from Twitter/X using the v2 API (Tweepy)."""
    console.print(f"Connecting to [bold cyan]Twitter V2 API[/bold cyan] for query: '{query}'")
    if not TWITTER_BEARER_TOKEN:
        logger.warning("TWITTER_BEARER_TOKEN not set. Skipping Twitter search.")
        return []

    try:
        client = TweepyClient(TWITTER_BEARER_TOKEN)
        # Query: has:images specifies to only return tweets with images
        response = client.search_recent_tweets(
            f"{query} has:images -is:retweet",
            tweet_fields=["created_at", "author_id"],
            expansions=["attachments.media_keys", "author_id"],
            media_fields=["url", "preview_image_url"],
            max_results=max(10, max_results) # API minimum is 10
        )
        
        results = []
        if not response.data:
            return []

        media_lookup = {m["media_key"]: m for m in response.includes.get("media", [])}
        user_lookup = {u["id"]: u for u in response.includes.get("users", [])}

        for tweet in response.data:
            if len(results) >= max_results:
                break
            if not tweet.attachments or not tweet.attachments.get("media_keys"):
                continue
            
            author_info = user_lookup.get(tweet.author_id, {})
            
            for key in tweet.attachments["media_keys"]:
                media = media_lookup.get(key)
                if media and media.type == "photo":
                    # 'media.url' is the high-res image URL
                    results.append({
                        "source_url": media.url,
                        "source_context_url": f"https://x.com/{author_info.get('username', 'user')}/status/{tweet.id}",
                        "source_type": ImageSourceType.TWITTER,
                        "metadata": {
                            "author": f"@{author_info.get('username', 'unknown')}",
                            "text": tweet.text,
                            "timestamp": tweet.created_at.isoformat()
                        }
                    })
        return results
    except Exception as e:
        logger.error(f"Failed to fetch from Twitter API: {e}")
        return []

def fetch_images_from_reverse_search(image_url: HttpUrl, provider: str = "tineye") -> List[Dict[str, Any]]:
    """Performs a reverse image search using TinEye or Google Vision."""
    console.print(f"Connecting to [bold green]{provider}[/bold green] for reverse search of: {image_url}")
    results = []
    
    if provider == "tineye":
        if not TINEYE_API_KEY:
            logger.warning("TINEYE_API_KEY not set. Skipping TinEye search.")
            return []
        try:
            api = TinEyeAPIRequest(api_key=TINEYE_API_KEY)
            response = api.search_url(str(image_url))
            for match in response.matches:
                results.append({
                    "source_url": image_url,
                    "source_context_url": match.backlinks[0].url if match.backlinks else match.domain,
                    "source_type": ImageSourceType.REVERSE_SEARCH,
                    "metadata": {"match_image_url": match.image_url, "provider": "tineye"}
                })
        except Exception as e:
            logger.error(f"TinEye API failed: {e}")
            
    elif provider == "google":
        if not gcp_vision_client:
            logger.warning("Google Vision client not initialized. Skipping Google reverse search.")
            return []
        try:
            image = vision.Image(source=vision.ImageSource(image_uri=str(image_url)))
            response = gcp_vision_client.web_detection(image=image)
            for page in response.web_detection.pages_with_matching_images:
                results.append({
                    "source_url": image_url,
                    "source_context_url": page.url,
                    "source_type": ImageSourceType.REVERSE_SEARCH,
                    "metadata": {"match_score": page.score, "provider": "google_vision"}
                })
        except Exception as e:
            logger.error(f"Google Vision API failed: {e}")
            
    else:
        logger.warning(f"Unknown reverse search provider: {provider}")

    return results


# --- 2. Core Ingestion Pipeline ---

def fetch_raw_image(url: HttpUrl) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetches the raw binary content of an image from a URL."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(str(url), headers=headers, timeout=10, stream=True)
        response.raise_for_status()
        
        content_type = response.headers.get("Content-Type")
        if not content_type or not content_type.startswith("image/"):
            logger.warning(f"URL {url} did not return an image. MIME: {content_type}")
            return None, None
            
        image_bytes = response.content
        return image_bytes, content_type
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch image from {url}: {e}")
        return None, None

def normalize_and_hash(
    image_bytes: bytes, 
    content_type: str
) -> Tuple[str, str, int, Optional[str], Optional[ExifData]]:
    """
    Calculates hashes, dimensions, and extracts EXIF data from raw image bytes.
    """
    sha256_hash = hashlib.sha256(image_bytes).hexdigest()
    file_size = len(image_bytes)
    resolution = None
    exif_data = {}

    try:
        with Image.open(BytesIO(image_bytes)) as img:
            resolution = f"{img.width}x{img.height}"
            exif = img.getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='replace')
                    if isinstance(value, str) and len(value) > 256:
                        value = value[:256] + "..."
                    # Handle specific types like IFDRational
                    if not isinstance(value, (str, int, float, bool, bytes, type(None))):
                         value = str(value)
                    exif_data[str(tag_name)] = value
                    
    except Exception as e:
        logger.warning(f"Could not open image to get dimensions/EXIF: {e}")

    pydantic_exif = ExifData(
        Make=exif_data.get("Make"),
        Model=exif_data.get("Model"),
        DateTime=exif_data.get("DateTimeOriginal") or exif_data.get("DateTime"),
        GPSInfo=exif_data.get("GPSInfo")
    )

    return sha256_hash, resolution, file_size, content_type, pydantic_exif


def store_raw_image(image_bytes: bytes, sha256_hash: str, content_type: str) -> str:
    """Stores the raw image bytes in S3 and returns the storage key."""
    if not s3_client:
        raise ConnectionError("S3 client is not initialized. Check credentials and bucket name.")
        
    extension_map = {"image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp"}
    extension = extension_map.get(content_type, content_type.split("/")[-1])
    s3_key = f"imint/raw/{sha256_hash}.{extension}"
    
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET, 
            Key=s3_key, 
            Body=image_bytes, 
            ContentType=content_type
        )
        logger.info(f"S3 Upload: Stored {len(image_bytes)} bytes to s3://{S3_BUCKET}/{s3_key}")
    except ClientError as e:
        logger.error(f"Failed to upload to S3: {e}")
        raise
        
    return s3_key


def index_features(image_bytes: bytes) -> ImageFeatures:
    """Calculates features (hashes, embeddings) for indexing."""
    logger.info("Calculating features (pHash, dHash, CLIP)...")
    
    phash, dhash = None, None
    embedding_shape, embedding_model = None, None
    
    # Perceptual & Difference Hashes
    try:
        img = Image.open(BytesIO(image_bytes))
        phash = str(imagehash.phash(img))
        dhash = str(imagehash.dhash(img))
    except Exception as e:
        logger.warning(f"Could not calculate image hashes: {e}")
        
    # ML Embeddings (CLIP)
    if clip_model and clip_processor:
        try:
            # Re-open image with PIL for the processor
            pil_image = Image.open(BytesIO(image_bytes))
            inputs = clip_processor(images=pil_image, return_tensors="pt", padding=True)
            
            with torch.no_grad():
                image_features = clip_model.get_image_features(**inputs)
            
            # image_features is the embedding. We store its shape.
            # The vector itself (image_features.numpy()) would be sent to a Vector DB.
            embedding_shape = str(tuple(image_features.shape))
            embedding_model = def_model
            logger.info(f"Generated CLIP embedding with shape {embedding_shape}")

        except Exception as e:
            logger.error(f"CLIP embedding failed: {e}")
    
    return ImageFeatures(
        perceptual_hash=phash,
        difference_hash=dhash,
        embedding_model_name=embedding_model,
        embedding_vector_shape=embedding_shape
    )

def enrich_image(image_bytes: bytes, pydantic_exif: Optional[ExifData]) -> ImageEnrichment:
    """Runs enrichment models (OCR, face, logo) on the image."""
    logger.info("Running enrichment (OCR, faces, logos)...")
    
    # --- OCR (EasyOCR) ---
    ocr_text = None
    if ocr_reader:
        try:
            results = ocr_reader.readtext(image_bytes, detail=0, paragraph=True)
            ocr_text = " ".join(results) if results else None
        except Exception as e:
            logger.error(f"EasyOCR failed: {e}")
    
    # --- Face Detection (OpenCV) ---
    face_count = 0
    face_locations = []
    if face_cascade:
        try:
            import numpy as np
            image_array = np.frombuffer(image_bytes, np.uint8)
            img_cv = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            face_count = len(faces)
            for (x, y, w, h) in faces:
                face_locations.append({"box": [int(x), int(y), int(w), int(h)], "confidence": None})
        except Exception as e:
            logger.error(f"OpenCV face detection failed: {e}")
            
    # --- Logo Detection (Google Vision) ---
    logos = []
    if gcp_vision_client:
        try:
            gcp_image = vision.Image(content=image_bytes)
            response = gcp_vision_client.logo_detection(image=gcp_image)
            for logo in response.logo_annotations:
                logos.append(logo.description)
        except Exception as e:
            logger.error(f"Google Vision logo detection failed: {e}")
    
    return ImageEnrichment(
        ocr_text=ocr_text,
        detected_logos=logos,
        detected_faces_count=face_count,
        face_locations=face_locations if face_locations else None,
        exif_data=pydantic_exif
    )

def store_metadata(record: IngestedImageRecord) -> str:
    """Stores the normalized metadata record in the PostgreSQL database."""
    logger.info(f"Storing metadata for {record.id} in PostgreSQL.")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS imint_ingestion_log (
                id VARCHAR(36) PRIMARY KEY,
                source_url TEXT,
                source_type VARCHAR(50),
                source_context_url TEXT,
                ingested_at TIMESTAMP WITH TIME ZONE,
                sha256_hash VARCHAR(64) UNIQUE,
                storage_key TEXT,
                features JSONB,
                enrichment JSONB,
                arg_node_id VARCHAR(255)
            );
        """)

        insert_query = """
            INSERT INTO imint_ingestion_log (
                id, source_url, source_type, source_context_url, 
                ingested_at, sha256_hash, storage_key, features, 
                enrichment, arg_node_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (sha256_hash) DO UPDATE SET
                source_url = EXCLUDED.source_url,
                source_context_url = EXCLUDED.source_context_url
            RETURNING id;
        """
        cursor.execute(
            insert_query,
            (
                record.id,
                str(record.source_url),
                record.source_type.value,
                str(record.source_context_url) if record.source_context_url else None,
                record.ingested_at,
                record.sha256_hash,
                record.storage_key,
                record.features.model_dump_json() if record.features else None,
                record.enrichment.model_dump_json() if record.enrichment else None,
                record.arg_node_id
            ),
        )
        returned_id = cursor.fetchone()[0]
        
        conn.commit()
        cursor.close()
        conn.close()
        
        if returned_id != record.id:
            logger.warning(f"Image with hash {record.sha256_hash} already exists. Updated existing record {returned_id}.")
            return returned_id
        else:
            return record.id
        
    except Exception as e:
        logger.error(f"Database Error: Could not log image metadata: {e}")
        raise

def link_to_arg(record: IngestedImageRecord) -> str:
    """Creates a node for the image in the ARG (Neo4j) and links it."""
    logger.info(f"Linking image {record.id} in ARG.")
    driver = get_graph_driver()
    if not driver:
        logger.warning("Graph DB not configured. Skipping ARG link.")
        return record.id 

    # The canonical ID for an image node is its hash.
    node_id = f"Image:{record.sha256_hash}"
    
    with driver.session() as session:
        # Create/merge the primary Image node
        session.run(
            """
            MERGE (i:Image {sha256: $sha256})
            ON CREATE SET
                i.id = $id, // Use the *first* UUID as the primary ID
                i.source_url = $source_url,
                i.storage_key = $storage_key,
                i.resolution = $resolution,
                i.source_type = $source_type,
                i.phash = $phash
            ON MATCH SET
                i.last_seen_url = $source_url // Update with the latest URL it was seen at
            """,
            sha256=record.sha256_hash,
            id=node_id,
            source_url=str(record.source_url),
            storage_key=record.storage_key,
            resolution=record.resolution,
            source_type=record.source_type.value,
            phash=record.features.perceptual_hash if record.features else None,
        )
        
        # Link to the source page (e.g., the Tweet or the Google Images result page)
        if record.source_context_url:
            session.run(
                """
                MERGE (p:WebPage {url: $url})
                MERGE (i:Image {sha256: $sha256})
                MERGE (p)-[r:CONTAINS_IMAGE]->(i)
                """,
                url=str(record.source_context_url),
                sha256=record.sha256_hash
            )
            
        # Link to entities from enrichment
        if record.enrichment:
            if record.enrichment.ocr_text:
                session.run(
                    "MERGE (i:Image {sha256: $sha256}) SET i.ocr_text = $text",
                    sha256=record.sha256_hash,
                    text=record.enrichment.ocr_text[:500]
                )
            
            for logo in record.enrichment.detected_logos:
                session.run(
                    """
                    MERGE (o:Organization {name: $name})
                    MERGE (i:Image {sha256: $sha256})
                    MERGE (i)-[r:DEPICTS_LOGO]->(o)
                    """,
                    name=logo,
                    sha256=record.sha256_hash
                )
    
    return node_id


# --- 3. Main Orchestration Function ---

def run_full_ingestion(
    source_url: HttpUrl,
    source_type: ImageSourceType,
    source_context_url: Optional[HttpUrl] = None,
    original_timestamp: Optional[datetime] = None,
) -> IngestedImageRecord:
    """
    Runs the complete ingestion and processing pipeline for a single image URL.
    """
    console.print(f"--- Starting IMINT Ingestion for: [cyan]{source_url}[/cyan] ---")
    record_id = str(uuid.uuid4())
    
    record = IngestedImageRecord(
        id=record_id,
        source_url=source_url,
        source_type=source_type,
        source_context_url=source_context_url,
        original_timestamp=original_timestamp,
        storage_key="N/A", 
        sha256_hash="N/A"
    )

    try:
        # 1. Fetch
        image_bytes, content_type = fetch_raw_image(source_url)
        if not image_bytes:
            raise ValueError("Failed to fetch image or content-type was not 'image'.")
        
        console.print(f"[green]✓[/green] Fetched: {len(image_bytes)} bytes ({content_type})")

        # 2. Normalize & Hash
        sha256, resolution, size, mime, exif = normalize_and_hash(image_bytes, content_type)
        record.sha256_hash = sha256
        record.resolution = resolution
        record.file_size_bytes = size
        record.mime_type = mime
        console.print(f"[green]✓[/green] Normalized: SHA256 [bold]{sha256[:10]}...[/bold], Res {resolution}")

        # 3. Store Raw Image
        storage_key = store_raw_image(image_bytes, sha256, content_type)
        record.storage_key = storage_key
        console.print(f"[green]✓[/green] Stored: [yellow]s3://{S3_BUCKET}/{storage_key}[/yellow]")

        # 4. Index Features
        features = index_features(image_bytes)
        record.features = features
        console.print(f"[green]✓[/green] Indexed: pHash [bold]{features.perceptual_hash}[/bold], Embed [bold]{features.embedding_vector_shape}[/bold]")

        # 5. Enrich
        enrichment = enrich_image(image_bytes, exif)
        record.enrichment = enrichment
        console.print(f"[green]✓[/green] Enriched: {enrichment.detected_faces_count} faces, {len(enrichment.detected_logos)} logos.")

        # 6. Link to ARG
        arg_node_id = link_to_arg(record)
        record.arg_node_id = arg_node_id
        console.print(f"[green]✓[/green] Linked: ARG Node [bold]{arg_node_id}[/bold]")

        # 7. Store Metadata
        db_id = store_metadata(record)
        if db_id != record.id:
            console.print(f"[yellow]i[/yellow] Metadata: Duplicate hash found, linked to existing record [bold]{db_id}[/bold].")
            record.id = db_id 
        else:
            console.print(f"[green]✓[/green] Finalized: Metadata stored in DB with ID [bold]{db_id}[/bold].")

    except Exception as e:
        logger.error(f"IMINT Ingestion Pipeline failed for {source_url}: {e}", exc_info=True)
        record.error = str(e)
        console.print(f"[red]✗[/red] Pipeline Failed: {e}")
        
    console.print(f"--- Ingestion Finished ---")
    return record


# --- 4. CLI Commands ---

@imint_ingestion_app.command("url", help="Ingest a single image from a direct URL.")
def cli_ingest_url(
    url: str = typer.Argument(..., help="The direct URL to the image."),
    source_type: ImageSourceType = typer.Option(
        ImageSourceType.OTHER, 
        "--source-type", 
        "-s", 
        help="The source category."
    ),
    context_url: Optional[str] = typer.Option(None, "--context-url", "-c", help="The page URL where the image was found."),
):
    """CLI to run the full ingestion pipeline on a single URL."""
    try:
        record = run_full_ingestion(
            source_url=HttpUrl(url),
            source_type=source_type,
            source_context_url=HttpUrl(context_url) if context_url else None
        )
        save_or_print_results(record.model_dump(), None)
        if record.error:
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@imint_ingestion_app.command("search", help="Find and ingest images from a source (e.g., Google, Twitter).")
def cli_ingest_search(
    query: str = typer.Argument(..., help="The search query."),
    source: ImageSourceType = typer.Option(
        ImageSourceType.GOOGLE_IMAGES,
        "--source",
        "-s",
        help="The data source to search."
    ),
    max_results: int = typer.Option(5, "--max", "-n", help="Max images to ingest."),
):
    """CLI to search a source and ingest the results."""
    
    console.print(f"--- Starting IMINT Search Ingestion ---")
    console.print(f"Query: [bold]{query}[/bold] | Source: [bold]{source.value}[/bold] | Max: [bold]{max_results}[/bold]")
    
    try:
        if source == ImageSourceType.GOOGLE_IMAGES:
            image_metas = fetch_images_from_google(query, max_results)
        elif source == ImageSourceType.TWITTER:
            image_metas = fetch_images_from_twitter(query, max_results)
        else:
            console.print(f"[bold red]Error:[/bold red] Source '{source.value}' is not a searchable source.")
            raise typer.Exit(code=1)

        console.print(f"Found {len(image_metas)} potential images.")
        
        final_records = []
        for meta in image_metas:
            ts = meta["metadata"].get("timestamp")
            original_ts = datetime.fromisoformat(ts) if ts else None
            
            record = run_full_ingestion(
                source_url=HttpUrl(meta["source_url"]),
                source_type=meta["source_type"],
                source_context_url=HttpUrl(meta["source_context_url"]),
                original_timestamp=original_ts
            )
            final_records.append(record.model_dump())
            
        console.print("\n--- [bold green]Search Ingestion Complete[/bold green] ---")
        save_or_print_results(final_records, None)
        
    except Exception as e:
        console.print(f"\n[bold red]An error occurred during search ingestion:[/bold red] {e}", exc_info=True)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    imint_ingestion_app()