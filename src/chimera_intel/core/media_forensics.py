"""
Deepfake & Photoshop Forensics Module

This module provides AI-driven tools to detect media manipulation,
verify provenance, and analyze disinformation campaigns.

NOTE ON DEPENDENCIES:
This module requires several new libraries. You will need to install them:
pip install pillow numpy tensorflow opencv-python c2pa-python httpx beautifulsoup4 python-whois scikit-learn networkx spacy newspaper3k dlib face_recognition h5py
python -m spacy download en_core_web_sm
"""

import typer
import json
import pathlib
import io
import re
import os
import cv2  
import numpy as np
import tensorflow as tf
import c2pa
import httpx
import whois
import newspaper
import spacy
import requests 
from typing import Optional, List, Dict, Any
from datetime import datetime
from PIL import Image, ImageChops, ImageEnhance, ExifTags
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import NMF
import networkx as nx
from rich.console import Console
from rich.table import Table
try:
    import face_recognition
except ImportError:
    face_recognition = None

from chimera_intel.core.schemas import (ForensicArtifactResult,
                                        DeepfakeAnalysisResult,
                                        ProvenanceResult,
                                        NarrativeMapResult,
                                        PoisoningDetectionResult)


# Load NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except IOError:
    print("Spacy model 'en_core_web_sm' not found.")
    print("Please run: python -m spacy download en_core_web_sm")
    nlp = None

console = Console()

# --- [USER MUST PROVIDE] ---
# Path to a pre-trained deepfake detection model.
# If not set, a default model will be downloaded.
DEEPFAKE_MODEL_PATH = os.environ.get("DEEPFAKE_MODEL_PATH", "")
MODEL_INPUT_SHAPE = (256, 256) # Model expects 256x256
deepfake_model = None
face_cascade = None

# Public URL for a pre-trained Keras XceptionNet model
# Model from: https://github.com/kai-ni/Deepfake-Detection-using-XceptionNet
DEFAULT_MODEL_URL = "https://media.githubusercontent.com/media/kai-ni/Deepfake-Detection-using-XceptionNet/main/xception.h5"

def _get_default_model_path() -> pathlib.Path:
    """Gets the default path for the cached model."""
    # Use a cache directory within the user's home
    cache_dir = pathlib.Path.home() / ".cache" / "chimera-intel"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "deepfake_xception.h5"

def _download_model(url: str, dest_path: pathlib.Path):
    """Downloads a model file with progress."""
    console.print(f"Downloading deepfake model to: {dest_path}")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            
            with open(dest_path, 'wb') as f:
                from rich.progress import track
                for chunk in track(
                    r.iter_content(chunk_size=8192), 
                    description="Downloading...",
                    total=total_size / 8192
                ): 
                    f.write(chunk)
        console.print("[bold green]Model downloaded successfully.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to download model:[/bold red] {e}")
        if dest_path.exists():
            dest_path.unlink() # Clean up partial download
        raise

def load_models():
    """Load AI models and CV classifiers into memory."""
    global deepfake_model, face_cascade, DEEPFAKE_MODEL_PATH
    
    # --- Load Deepfake Model ---
    model_path_to_load = DEEPFAKE_MODEL_PATH
    
    if not model_path_to_load:
        # If no path is set via env var, use the default cache path
        model_path_to_load = _get_default_model_path()
        
        if not model_path_to_load.exists():
            # Download the model if it doesn't exist at the cache path
            try:
                _download_model(DEFAULT_MODEL_URL, model_path_to_load)
            except Exception:
                console.print("[bold red]Could not download default deepfake model. Deepfake scanning disabled.[/bold red]")
                model_path_to_load = "" # Prevent load attempt
    
    if not deepfake_model and model_path_to_load and pathlib.Path(model_path_to_load).exists():
        try:
            deepfake_model = tf.keras.models.load_model(str(model_path_to_load))
            console.print(f"Successfully loaded deepfake model from {model_path_to_load}")
            # The downloaded model expects (256, 256, 3)
            # Let's ensure our shape matches the loaded model
            global MODEL_INPUT_SHAPE
            # Get the shape from the model's input layer
            MODEL_INPUT_SHAPE = tuple(deepfake_model.input_shape[1:3]) # (height, width)
            console.print(f"Model input shape set to: {MODEL_INPUT_SHAPE}")

        except Exception as e:
            console.print(f"Warning: Could not load deepfake model from {model_path_to_load}: {e}")
            console.print("This may be due to a TensorFlow/h5py version mismatch.")
    elif not deepfake_model:
        console.print("Warning: Deepfake model not loaded.")
        console.print("Deepfake scanning will be limited.")

    # --- Load OpenCV Face Classifier ---
    try:
        # Get the path to the cascade file
        cascade_path = pathlib.Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
        if not cascade_path.exists():
            raise FileNotFoundError(f"Could not find Haarcascade file at {cascade_path}")
        face_cascade = cv2.CascadeClassifier(str(cascade_path))
        console.print("Successfully loaded OpenCV face cascade.")
    except Exception as e:
        console.print(f"Error: Could not load OpenCV face cascade: {e}")
        print("Face detection for deepfake scanning will be disabled.")


# --- Core Logic Functions (Real Implementations) ---

def forensic_artifact_scan(file_path: pathlib.Path) -> ForensicArtifactResult:
    """
    Scans an image for forensic artifacts using Error Level Analysis (ELA)
    and EXIF metadata checks.
    """
    result = ForensicArtifactResult(file_path=str(file_path))
    artifacts = []
    confidences = {}

    try:
        original_image = Image.open(file_path).convert("RGB")

        # 1. EXIF Metadata Analysis
        exif_data = original_image.getexif()
        if exif_data:
            software_tag = ExifTags.TAGS.get(305)  # 305 is the 'Software' tag
            if software_tag in exif_data:
                software = exif_data[software_tag]
                if "photoshop" in software.lower() or "gimp" in software.lower():
                    artifacts.append("Manipulation Software (Photoshop/GIMP) in EXIF")
                    confidences["EXIF Software"] = 0.75

        # 2. Error Level Analysis (ELA)
        buffer = io.BytesIO()
        original_image.save(buffer, format="JPEG", quality=90)
        buffer.seek(0)
        resaved_image = Image.open(buffer)

        # Find the difference
        ela_image = ImageChops.difference(original_image, resaved_image)
        
        # Brighten the ELA image
        extrema = ela_image.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        if max_diff == 0:
            max_diff = 1 # Avoid division by zero
            
        scale = 255.0 / max_diff
        # Enhance brightness significantly to make artifacts visible
        ela_image = ImageEnhance.Brightness(ela_image).enhance(scale * 10) 

        # Simple heuristic: high variance in ELA suggests tampering.
        # A real tool would use a dedicated CNN on the ELA image.
        ela_array = np.array(ela_image.convert("L")) # Grayscale
        variance = ela_array.std()

        # Threshold is empirical; high-compression originals also have high variance
        if variance > 20: 
            artifacts.append("High Variance Error Level Analysis (ELA)")
            confidences["ELA Variance"] = min(variance / 30, 1.0) # Normalized confidence

        result.artifacts_found = artifacts
        result.confidence_scores = confidences

    except Exception as e:
        result.error = f"Failed to perform artifact scan: {e}"

    return result


def deepfake_multimodal_scan(file_path: pathlib.Path) -> DeepfakeAnalysisResult:
    """
    Scans a video file for signs of deepfakes by detecting faces
    and passing them to a loaded AI model.
    """
    result = DeepfakeAnalysisResult(file_path=str(file_path))
    if not deepfake_model:
        result.error = "No deepfake detection model is loaded. Run 'load_models' or check config."
        return result
    if not face_cascade:
        result.error = "No OpenCV face cascade is loaded. Cannot detect faces."
        return result

    try:
        cap = cv2.VideoCapture(str(file_path))
        frame_predictions = []
        frames_processed = 0
        
        while cap.isOpened() and frames_processed < 150: # Limit to 150 frames
            ret, frame = cap.read()
            if not ret:
                break
            
            frames_processed += 1
            # Convert to grayscale for face detection
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Detect faces
            faces = face_cascade.detectMultiScale(gray_frame, 1.1, 4)
            
            # Process each face found
            for (x, y, w, h) in faces:
                # Crop the face
                face = frame[y:y+h, x:x+w]
                
                # Pre-process for the model (must match model's training)
                try:
                    # Resize to the model's expected input shape
                    processed_face = cv2.resize(face, MODEL_INPUT_SHAPE) 
                    # The XceptionNet model expects pixel values in [-1, 1]
                    processed_face = (processed_face / 255.0) * 2.0 - 1.0
                    processed_face = np.expand_dims(processed_face, axis=0) # Add batch dim
                except Exception as e:
                    print(f"Skipping face: could not resize. Error: {e}")
                    continue

                # Pass face to the loaded model
                prediction = deepfake_model.predict(processed_face, verbose=0)[0]
                # The model outputs [prob_real, prob_fake]
                fake_prob = prediction[1] 
                frame_predictions.append(fake_prob)

        cap.release()

        if not frame_predictions:
            result.error = "Could not detect any faces in the video."
            return result
        
        avg_fake_prob = np.mean(frame_predictions)
        if avg_fake_prob > 0.5: # 50% confidence threshold
            result.is_deepfake = True
            result.confidence = float(avg_fake_prob)
            result.inconsistencies = [f"High average fake probability ({avg_fake_prob:.2f}) across {len(frame_predictions)} detected faces."]
        else:
            result.is_deepfake = False
            result.confidence = 1.0 - float(avg_fake_prob) # Confidence in authenticity
            result.inconsistencies = [f"Low average fake probability ({avg_fake_prob:.2f})."]

    except Exception as e:
        result.error = f"Failed during deepfake analysis: {e}"
        if cap and cap.isOpened():
            cap.release()
            
    return result


def content_provenance_check(file_path: pathlib.Path) -> ProvenanceResult:
    """
    Checks for C2PA (Content Provenance and Authenticity)
    credentials embedded in the media file using the official c2pa library.
    """
    result = ProvenanceResult(file_path=str(file_path))
    try:
        manifest_store = c2pa.read_file(str(file_path))

        if not manifest_store:
            result.error = "No C2PA manifest found."
            return result

        result.has_c2pa_credentials = True
        
        manifest = manifest_store.get_active()
        if not manifest:
            result.error = "C2PA data found, but no active manifest."
            return result

        result.issuer = manifest.get("issuer")
        
        # A simple validity check
        if result.issuer:
            result.is_valid = True 
        
        # Extract history
        assertions = manifest.get("assertions", [])
        history = []
        for assertion in assertions:
            action = assertion.get("data", {}).get("action")
            if action:
                history.append({"action": action})
        result.manifest_history = history

    except Exception as e:
        result.error = f"Failed to read C2PA data: {e}"

    return result


def synthetic_narrative_map(topic: str) -> NarrativeMapResult:
    """
    Maps a coordinated influence campaign by fetching REAL related articles
    (via Google News), performing topic modeling, and building a narrative graph.
    """
    result = NarrativeMapResult(topic=topic)
    
    # 1. Real Data Ingestion (using newspaper3k)
    # Build a source URL (e.g., Google News)
    url = f'https://news.google.com/search?q={topic.replace(" ", "%20")}&hl=en-US&gl=US&ceid=US:en'
    
    try:
        # Build a "source" from the search URL
        news_source = newspaper.build(url, memoize_articles=False)
        documents = []
        
        # Download and parse the top 10 articles
        for article in news_source.articles[:10]:
            try:
                article.download()
                article.parse()
                if article.text:
                    documents.append(article.text)
            except newspaper.article.ArticleException:
                continue # Skip articles that fail to download/parse
        
        if not documents:
            result.error = "Could not find or parse any articles for this topic."
            return result

        # 2. Topic Modeling (find key narratives)
        tfidf_vectorizer = TfidfVectorizer(max_df=0.95, min_df=2, stop_words="english", max_features=100)
        tfidf = tfidf_vectorizer.fit_transform(documents)
        
        n_components = min(3, len(documents), tfidf.shape[1])
        if n_components < 1:
             result.error = "Not enough unique text to perform topic modeling."
             return result

        nmf = NMF(n_components=n_components, random_state=1).fit(tfidf)
        
        feature_names = tfidf_vectorizer.get_feature_names_out()
        key_narratives = []
        for topic_idx, topic_vec in enumerate(nmf.components_):
            narrative = " ".join(
                [feature_names[i] for i in topic_vec.argsort()[:-5 - 1:-1]]
            )
            key_narratives.append(f"Narrative {topic_idx+1}: {narrative}")
        result.key_narratives = key_narratives

        # 3. Graph Analysis (Simulated)
        # TODO: A real implementation would require a massive social graph DB
        G = nx.DiGraph()
        # Simulate origin nodes based on article sources
        for i, article in enumerate(news_source.articles[:len(documents)]):
            domain = article.source_url.split("://")[-1].split("/")[0] if article.source_url else f"Source {i}"
            G.add_node(domain, type="origin")
            # Connect source to the narrative it most closely matches
            if n_components > 0:
                doc_topic_dist = nmf.transform(tfidf[i:i+1])
                narrative_idx = doc_topic_dist.argmax()
                G.add_edge(domain, key_narratives[narrative_idx])

        result.origin_nodes = [
            n for n, d in G.nodes(data=True) if d.get("type") == "origin"
        ]
        
        # 4. Velocity (Simulated placeholder)
        result.spread_velocity = np.random.rand() * 10 
        
    except Exception as e:
        result.error = f"Failed to map narrative: {e}"

    return result


def source_poisoning_detect(source_url: str) -> PoisoningDetectionResult:
    """
    Detects if an OSINT source (e.g., a news blog) is being 'poisoned'
    with coordinated disinformation using a heuristic-based check.
    """
    result = PoisoningDetectionResult(source_url=source_url)
    indicators = []
    confidence = 0.0
    domain = ""

    try:
        # 1. Check domain registration (WHOIS)
        domain_match = re.search(r"https?://([A-Za-z0-9\.-]+)/?", source_url)
        if domain_match:
            domain = domain_match.group(1)
            try:
                domain_info = whois.query(domain)
                if domain_info and domain_info.creation_date:
                    # Handle lists of dates
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    if creation_date:
                        age = (datetime.now() - creation_date).days
                        if age < 180: # Less than 6 months old
                            indicators.append(f"Source domain is very new ({age} days old)")
                            confidence += 0.3
            except Exception as e:
                print(f"WHOIS check failed for {domain}: {e}") # Non-critical

        # 2. Analyze page content for indicators
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        }
        with httpx.Client(timeout=10.0) as client:
            response = client.get(source_url, headers=headers, follow_redirects=True)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.get_text().lower()

            # 3. Check for high-emotion / charged language
            if nlp and text:
                doc = nlp(text[:20000]) # Limit analysis
                polarizing_words = ["outrage", "conspiracy", "fake", "must", "shocking", "corrupt", "deep state", "hoax"]
                count = sum([1 for token in doc if token.lemma_ in polarizing_words])
                if count > 5:
                    indicators.append(f"High count ({count}) of emotionally charged keywords")
                    confidence += 0.2
            
            # 4. Check for signs of coordinated content
            if "many sources are saying" in text or "everyone is talking about" in text:
                indicators.append("Vague sourcing / appeal to anonymous majority")
                confidence += 0.15

        result.indicators = indicators
        result.confidence = min(confidence, 1.0)
        if result.confidence > 0.4: # Lowered threshold
            result.is_compromised = True

    except Exception as e:
        result.error = f"Failed to analyze source: {e}"

    return result


# --- Face Recognition ---

def _check_face_rec_imports():
    """Checks if face_recognition is installed."""
    if face_recognition is None:
        console.print("[bold red]Error: 'face_recognition' library not installed.[/bold red]")
        console.print("Please run: [cyan]pip install dlib face_recognition[/cyan]")
        console.print("Note: 'dlib' may require C++ build tools (like CMake) to be installed first.")
        raise typer.Exit(code=1)

def find_faces(image_path: pathlib.Path, model: str = "hog") -> List[Dict[str, Any]]:
    """Finds faces in an image and returns their locations."""
    _check_face_rec_imports()
    try:
        image = face_recognition.load_image_file(str(image_path))
        face_locations = face_recognition.face_locations(image, model=model)
        
        results = []
        for i, (top, right, bottom, left) in enumerate(face_locations):
            results.append({
                "face_id": i + 1,
                "location_box": f"({top}, {right}, {bottom}, {left})"
            })
        return results
    except Exception as e:
        console.print(f"[bold red]Error during face detection:[/bold red] {e}")
        raise typer.Exit(code=1)

def get_face_encodings(image_path: pathlib.Path) -> List[List[float]]:
    """Generates 128-d face encodings for all faces in an image."""
    _check_face_rec_imports()
    try:
        image = face_recognition.load_image_file(str(image_path))
        # Find locations first
        face_locations = face_recognition.face_locations(image)
        if not face_locations:
            return []
        
        # Get encodings for the found locations
        encodings = face_recognition.face_encodings(image, known_face_locations=face_locations)
        # Convert numpy arrays to lists for JSON serialization
        return [enc.tolist() for enc in encodings]
    except Exception as e:
        console.print(f"[bold red]Error generating face encodings:[/bold red] {e}")
        raise typer.Exit(code=1)

def compare_faces(
    known_image_path: pathlib.Path,
    unknown_image_path: pathlib.Path,
    tolerance: float = 0.6
) -> List[Dict[str, Any]]:
    """Compares faces in an unknown image against a known image."""
    _check_face_rec_imports()
    try:
        # Load known image and get first encoding
        known_image = face_recognition.load_image_file(str(known_image_path))
        known_encodings = face_recognition.face_encodings(known_image)
        
        if not known_encodings:
            console.print(f"[bold red]Error:[/bold red] No faces found in known image '{known_image_path.name}'.")
            raise typer.Exit(code=1)
        
        # Use only the first known face
        known_encoding = known_encodings[0]

        # Load unknown image and get all encodings
        unknown_image = face_recognition.load_image_file(str(unknown_image_path))
        unknown_locations = face_recognition.face_locations(unknown_image)
        unknown_encodings = face_recognition.face_encodings(unknown_image, known_face_locations=unknown_locations)

        if not unknown_encodings:
            console.print(f"[bold yellow]Warning:[/bold yellow] No faces found in unknown image '{unknown_image_path.name}'.")
            return []
        
        results = []
        for i, (unknown_encoding, location) in enumerate(zip(unknown_encodings, unknown_locations)):
            # See if the face is a match
            matches = face_recognition.compare_faces([known_encoding], unknown_encoding, tolerance=tolerance)
            # Get distance (lower is better)
            face_distance = face_recognition.face_distance([known_encoding], unknown_encoding)[0]
            
            results.append({
                "face_id": i + 1,
                "location": f"({location[0]}, {location[1]}, {location[2]}, {location[3]})",
                "is_match": bool(matches[0]),
                "distance": float(face_distance),
                "tolerance": tolerance
            })
        return results
    except Exception as e:
        console.print(f"[bold red]Error comparing faces:[/bold red] {e}")
        raise typer.Exit(code=1)


# --- Typer CLI Application ---

forensics_app = typer.Typer(
    help="Deepfake & Photoshop Forensics and Disinformation Analysis."
)

@forensics_app.callback()
def main():
    """Load models when the CLI app is first invoked."""
    load_models()


@forensics_app.command("artifact-scan", help="Scan media for forensic manipulation artifacts.")
def cli_artifact_scan(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the media file."),
    output: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Path to save JSON result.")
):
    """CLI command for forensic_artifact_scan."""
    result = forensic_artifact_scan(file_path)
    output_data = result.model_dump_json(indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        typer.echo(f"Forensic scan complete. Results saved to: {output}")
    else:
        typer.echo(output_data)


@forensics_app.command("deepfake-scan", help="Run multimodal deepfake detection.")
def cli_deepfake_scan(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the video/audio file."),
    output: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Path to save JSON result.")
):
    """CLI command for deepfake_multimodal_scan."""
    console.print(f"Scanning for deepfake indicators in: [cyan]{file_path.name}[/cyan]")
    result = deepfake_multimodal_scan(file_path)
    
    if result.error:
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        raise typer.Exit(code=1)

    # Pretty print table for deepfake results
    table = Table(title="Deepfake Scan Results")
    table.add_column("Property", style="magenta")
    table.add_column("Value", style="cyan")
    
    table.add_row("File", str(file_path.name))
    is_fake_str = "[bold red]Yes[/bold red]" if result.is_deepfake else "[bold green]No[/bold green]"
    table.add_row("Deepfake Detected", is_fake_str)
    table.add_row("Confidence", f"{result.confidence:.2%}")
    table.add_row("Details", "\n".join(result.inconsistencies))
    console.print(table)
    
    output_data = result.model_dump_json(indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        typer.echo(f"Deepfake scan complete. Results saved to: {output}")


@forensics_app.command("provenance-check", help="Verify media provenance using C2PA.")
def cli_provenance_check(
    file_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the media file."),
    output: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Path to save JSON result.")
):
    """CLI command for content_provenance_check."""
    result = content_provenance_check(file_path)
    output_data = result.model_dump_json(indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        typer.echo(f"Provenance check complete. Results saved to: {output}")
    else:
        typer.echo(output_data)


@forensics_app.command("map-narrative", help="Map synthetic narratives for a topic.")
def cli_map_narrative(
    topic: str = typer.Argument(..., help="The topic or keyword to analyze."),
    output: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Path to save JSON result.")
):
    """CLI command for synthetic_narrative_map."""
    result = synthetic_narrative_map(topic)
    output_data = result.model_dump_json(indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        typer.echo(f"Narrative map complete. Results saved to: {output}")
    else:
        typer.echo(output_data)


@forensics_app.command("detect-poisoning", help="Detect poisoning of an OSINT source.")
def cli_detect_poisoning(
    source_url: str = typer.Argument(..., help="The URL of the source to check."),
    output: Optional[pathlib.Path] = typer.Option(None, "--output", "-o", help="Path to save JSON result.")
):
    """CLI command for source_poisoning_detect."""
    result = source_poisoning_detect(source_url)
    output_data = result.model_dump_json(indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_data)
        typer.echo(f"Source poisoning check complete. Results saved to: {output}")
    else:
        typer.echo(output_data)


# --- Face Recognition CLI ---

@forensics_app.command("face-recognize", help="Find, encode, or compare faces in images.")
def cli_face_recognize(
    image_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the primary image file."
    ),
    compare_path: Optional[pathlib.Path] = typer.Option(
        None,
        "--compare",
        "-c",
        exists=True,
        help="Path to a second image to compare against.",
    ),
    mode: str = typer.Option(
        "find",
        "--mode",
        "-m",
        help="Mode: 'find' (locate faces), 'encode' (get 128-d encodings), 'compare' (match faces).",
    ),
    output: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Path to save JSON result."
    ),
):
    """
    Performs face detection, encoding, or comparison using dlib.
    
    - 'find': Locates all faces in [IMAGE_PATH].
    - 'encode': Generates 128-d encodings for all faces in [IMAGE_PATH].
    - 'compare': Compares the first face in [IMAGE_PATH] (as 'known')
                 against all faces in [COMPARE_PATH] (as 'unknown').
    """
    mode = mode.lower()
    
    if mode == "find":
        console.print(f"Finding faces in: [cyan]{image_path.name}[/cyan]")
        results = find_faces(image_path)
        console.print(f"Found {len(results)} face(s).")
        
    elif mode == "encode":
        console.print(f"Generating encodings for faces in: [cyan]{image_path.name}[/cyan]")
        results = get_face_encodings(image_path)
        console.print(f"Generated {len(results)} encoding(s).")
        
    elif mode == "compare":
        if not compare_path:
            console.print("[bold red]Error:[/bold red] --compare <path> is required for 'compare' mode.")
            raise typer.Exit(code=1)
        console.print(f"Comparing faces in [cyan]{compare_path.name}[/cyan] against [cyan]{image_path.name}[/cyan]")
        results = compare_faces(image_path, compare_path)
        
        # Pretty print table for compare mode
        table = Table(title="Face Comparison Results")
        table.add_column("Face ID (Unknown)", style="magenta")
        table.add_column("Match", style="cyan")
        table.add_column("Distance (Lower is Better)", style="yellow")
        
        for res in results:
            match_str = "[bold green]Yes[/bold green]" if res["is_match"] else "[bold red]No[/bold red]"
            table.add_row(str(res["face_id"]), match_str, f"{res['distance']:.4f}")
        console.print(table)
        
    else:
        console.print(f"[bold red]Error:[/bold red] Invalid mode '{mode}'. Must be 'find', 'encode', or 'compare'.")
        raise typer.Exit(code=1)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"Results saved to: {output}")
    elif mode != "compare": # Compare mode prints its own table
        console.print(json.dumps(results, indent=2))


if __name__ == "__main__":
    forensics_app()