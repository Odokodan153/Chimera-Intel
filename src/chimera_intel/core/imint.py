"""
Module for Image & Visual Intelligence (IMINT/VISINT).

Provides tools to extract metadata from images, analyze visual content,
perform object detection on satellite imagery, and detect changes between images.
"""

import typer
import logging
import os
import pathlib
from typing import Optional, Dict, Any
from PIL import Image
from PIL.ExifTags import TAGS
from rich.console import Console
import google.generativeai as genai

# Import for local OCR
try:
    import pytesseract
except ImportError:
    pytesseract = None

# Imports for Satellite Analysis & Change Detection
try:
    import cv2
    import numpy as np
except ImportError:
    print(
        "ERROR: Missing 'opencv-python-headless'. Please run: pip install opencv-python-headless"
    )
    cv2 = None
    np = None


from typing_extensions import Annotated
import torch
from torchvision import models, transforms

from .schemas import ImageAnalysisResult, ExifData
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)
console = Console()
imint_app = typer.Typer(
    name="imint",
    help="Imagery & Visual Intelligence (IMINT/VISINT)",
)


# --- Visual Intelligence (VISINT) ---


def analyze_image_content(image_path: str, prompt: str) -> str:
    """
    Analyzes the content of an image using a vision-capable AI model.
    """
    api_key = API_KEYS.google_api_key
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not found in .env file.")
    genai.configure(api_key=api_key)

    img = Image.open(image_path)
    model = genai.GenerativeModel("gemini-pro-vision")
    response = model.generate_content([prompt, img])

    return response.text


@imint_app.command(
    name="analyze-content", help="Analyze the content of an image using AI vision."
)
def analyze_content(
    image_path: str = typer.Argument(..., help="Path to the image file to analyze."),
    feature: str = typer.Option(
        ...,
        "--feature",
        "-f",
        help="Analysis feature: ocr, objects, logo, location, body-language, event.",
    ),
):
    """
    Uses a vision-capable AI model to extract intelligence from visual media,
    such as identifying objects, text, and analyzing human behavior.
    """
    console.print(
        f"Analyzing content of '{image_path}' for feature: [bold cyan]{feature}[/bold cyan]"
    )
    if not os.path.exists(image_path):
        console.print(
            f"[bold red]Error:[/bold red] Image file not found at '{image_path}'"
        )
        raise typer.Exit(code=1)
    prompts = {
        "ocr": "Extract all text from this image. Provide only the text.",
        "objects": "Identify and list all distinct objects in this image.",
        "logo": "Identify the brand or logo in this image. If none, say 'No logo found'.",
        "location": "Based on visual cues and landmarks, what is the likely geographic location of this photo?",
        "body-language": "Analyze the body language of the person or people in this image. Describe their posture, gestures, facial expressions, and likely emotional state. Infer the social dynamics if multiple people are present.",
        # +++ NEW FEATURE (POINT 3) +++
        "event": "Analyze the image for significant events. Identify any signs of protests, accidents, unusual gatherings, or emergency situations. Describe the event and the key visual indicators.",
    }

    prompt = prompts.get(feature.lower())
    if not prompt:
        console.print(
            f"[bold red]Error:[/bold red] Invalid feature '{feature}'. Valid options are: ocr, objects, logo, location, body-language, event."
        )
        raise typer.Exit(code=1)
    try:
        result_text = analyze_image_content(image_path, prompt)
        console.print("\n--- [bold green]Visual Analysis Result[/bold green] ---")
        console.print(result_text)
        console.print("---------------------------------")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during AI content analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


# --- [NEW] Local OCR (Pytesseract) ---


def perform_local_ocr(image_path: pathlib.Path) -> str:
    """
    Performs Optical Character Recognition (OCR) on a local image
    using the Tesseract engine.
    """
    if pytesseract is None:
        raise ImportError(
            "pytesseract not installed. Please run 'pip install pytesseract'."
        )
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text
    except pytesseract.TesseractNotFoundError:
        console.print(
            "[bold red]Error: Tesseract OCR engine not found.[/bold red]"
        )
        console.print(
            "Please install it from: https://github.com/tesseract-ocr/tesseract"
        )
        raise typer.Exit(code=1)
    except Exception as e:
        raise RuntimeError(f"An error occurred during OCR: {e}")


@imint_app.command(
    name="ocr", help="Extract text from an image using local Tesseract OCR."
)
def cli_local_ocr(
    image_path: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the image file to analyze."
    ),
):
    """
    Extracts text from an image using the local Tesseract OCR engine.
    This is a local, offline alternative to the 'analyze-content --feature ocr'
    command, which uses a cloud AI.
    """
    console.print(f"Performing local OCR on: [bold cyan]{image_path}[/bold cyan]")
    try:
        ocr_text = perform_local_ocr(image_path)
        console.print("\n--- [bold green]Local OCR Result[/bold green] ---")
        console.print(ocr_text)
        console.print("----------------------------------")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during local OCR:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


# --- Satellite Imagery Analysis ---

# Load a pre-trained model for object detection
detection_model = models.detection.fasterrcnn_resnet50_fpn(pretrained=True)
detection_model.eval()

COCO_INSTANCE_CATEGORY_NAMES = [
    "__background__",
    "person",
    "bicycle",
    "car",
    "motorcycle",
    "airplane",
    "bus",
    "train",
    "truck",
    "boat",
    "traffic light",
    "fire hydrant",
    "N/A",
    "stop sign",
    "parking meter",
    "bench",
    "bird",
    "cat",
    "dog",
    "horse",
    "sheep",
    "cow",
    "elephant",
    "bear",
    "zebra",
    "giraffe",
    "N/A",
    "backpack",
    "umbrella",
    "N/A",
    "N/A",
    "handbag",
    "tie",
    "suitcase",
    "frisbee",
    "skis",
    "snowboard",
    "sports ball",
    "kite",
    "baseball bat",
    "baseball glove",
    "skateboard",
    "surfboard",
    "tennis racket",
    "bottle",
    "N/A",
    "wine glass",
    "cup",
    "fork",
    "knife",
    "spoon",
    "bowl",
    "banana",
    "apple",
    "sandwich",
    "orange",
    "broccoli",
    "carrot",
    "hot dog",
    "pizza",
    "donut",
    "cake",
    "chair",
    "couch",
    "potted plant",
    "bed",
    "N/A",
    "dining table",
    "N/A",
    "N/A",
    "toilet",
    "N/A",
    "tv",
    "laptop",
    "mouse",
    "remote",
    "keyboard",
    "cell phone",
    "microwave",
    "oven",
    "toaster",
    "sink",
    "refrigerator",
    "N/A",
    "book",
    "clock",
    "vase",
    "scissors",
    "teddy bear",
    "hair drier",
    "toothbrush",
]


def perform_object_detection(image_path: str) -> dict:
    """
    Performs object detection on an image using a pre-trained model.
    """
    img = Image.open(image_path).convert("RGB")
    transform = transforms.Compose([transforms.ToTensor()])
    img_tensor = transform(img)

    with torch.no_grad():
        prediction = detection_model([img_tensor])
    detected_objects: Dict[str, int] = {}
    pred_labels = [
        COCO_INSTANCE_CATEGORY_NAMES[i] for i in prediction[0]["labels"].numpy()
    ]

    for label in pred_labels:
        detected_objects[label] = detected_objects.get(label, 0) + 1
    return detected_objects


@imint_app.command(
    name="analyze-satellite", help="Analyze satellite imagery for a given location."
)
def analyze_satellite(
    coords: Annotated[
        str,
        typer.Option(
            "--coords",
            "-c",
            help="The coordinates to analyze (e.g., '40.7128,-74.0060').",
        ),
    ],
    feature: Annotated[
        str,
        typer.Option(
            "--feature",
            "-f",
            help="The analysis feature to use (e.g., object-detection).",
        ),
    ],
    image_path: Annotated[
        str,
        typer.Option(
            "--image", "-i", help="Path to a local satellite image for analysis."
        ),
    ] = "",
):
    """
    Monitors physical locations from space to detect changes, identify assets,
    and analyze activity at a target's facilities.
    """
    console.print(
        f"Analyzing satellite imagery for coordinates: {coords} using feature: {feature}"
    )

    if feature.lower() == "object-detection":
        if not image_path:
            console.print(
                "[bold red]Error:[/bold red] The --image option is required for object detection."
            )
            raise typer.Exit(code=1)
        if not os.path.exists(image_path):
            console.print(
                f"[bold red]Error:[/bold red] Image file not found at '{image_path}'"
            )
            raise typer.Exit(code=1)
        try:
            detected_objects = perform_object_detection(image_path)
            console.print("\n--- [bold green]Object Detection Results[/bold green] ---")
            for obj, count in detected_objects.items():
                console.print(f"- Detected {count} instance(s) of '{obj}'")
            console.print("---------------------------------")
        except Exception as e:
            console.print(
                f"[bold red]An error occurred during object detection:[/bold red] {e}"
            )
            raise typer.Exit(code=1)
    else:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Feature '{feature}' is not yet implemented."
        )


# --- EXIF and Metadata Analysis ---


def analyze_image_metadata(file_path: str) -> ImageAnalysisResult:
    """
    Extracts EXIF metadata from an image file.

    Args:
        file_path (str): The path to the image file.

    Returns:
        ImageAnalysisResult: A Pydantic model with the extracted metadata.
    """
    try:
        with Image.open(file_path) as img:
            exif_data_raw = img._getexif()
            if not exif_data_raw:
                return ImageAnalysisResult(
                    file_path=file_path, message="No EXIF metadata found."
                )
            exif_data: Dict[str, Any] = {}
            for tag, value in exif_data_raw.items():
                decoded_tag = TAGS.get(tag, tag)
                exif_data[str(decoded_tag)] = str(value)
            return ImageAnalysisResult(
                file_path=file_path, exif_data=ExifData(**exif_data)
            )
    except Exception as e:
        return ImageAnalysisResult(
            file_path=file_path, error=f"Could not process image: {e}"
        )


@imint_app.command("metadata")
def run_image_metadata_analysis(
    file_path: str = typer.Argument(..., help="Path to the image file to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Extracts and analyzes EXIF metadata from an image file.
    """
    results_model = analyze_image_metadata(file_path)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=file_path, module="imint_metadata", data=results_dict)

def compare_image_changes(
    image_before_path: str, image_after_path: str, output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Compares two images and highlights the differences.
    Useful for satellite change detection.
    """
    if cv2 is None or np is None:
        raise ImportError("OpenCV is required for change detection.")

    try:
        image_before = cv2.imread(image_before_path)
        image_after = cv2.imread(image_after_path)

        if image_before is None or image_after is None:
            raise FileNotFoundError("Could not read one or both images.")

        # Resize images to be the same size for comparison
        h, w, _ = image_before.shape
        image_after = cv2.resize(image_after, (w, h))

        # Convert to grayscale
        gray_before = cv2.cvtColor(image_before, cv2.COLOR_BGR2GRAY)
        gray_after = cv2.cvtColor(image_after, cv2.COLOR_BGR2GRAY)

        # Compute the absolute difference
        (score, diff) = cv2.absdiff(gray_before, gray_after)
        diff_score = np.sum(diff) / (h * w)  # Average difference per pixel

        # Threshold the diff
        _, thresh = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)

        # Find contours
        contours, _ = cv2.findContours(
            thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )

        change_areas = len(contours)
        status = "No significant change"
        if diff_score > 1.0 and change_areas > 5:
            status = "Significant change detected"
        elif diff_score > 0.5 and change_areas > 0:
            status = "Minor change detected"

        if output_path:
            # Draw rectangles around changes on the 'after' image
            for c in contours:
                if cv2.contourArea(c) > 100:  # Filter small noise
                    (x, y, w, h) = cv2.boundingRect(c)
                    cv2.rectangle(image_after, (x, y), (x + w, y + h), (0, 0, 255), 2)
            cv2.imwrite(output_path, image_after)

        return {
            "status": status,
            "difference_score": round(diff_score, 4),
            "change_areas_found": change_areas,
            "output_image": output_path,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@imint_app.command(
    "change-detect",
    help="Compare two images to detect changes (e.g., satellite photos).",
)
def cli_change_detect(
    image_before: str = typer.Argument(..., help="Path to the 'before' image."),
    image_after: str = typer.Argument(..., help="Path to the 'after' image."),
    output_image: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save a new image highlighting the changes.",
    ),
):
    """
    Analyzes two images to find and optionally highlight differences.
    """
    console.print(
        f"Comparing [bold cyan]{image_before}[/] (Before) with [bold cyan]{image_after}[/] (After)"
    )
    try:
        results = compare_image_changes(image_before, image_after, output_image)
        console.print(f"Status: {results['status']}")
        console.print(f"Difference Score: {results['difference_score']}")
        console.print(f"Change Areas Found: {results['change_areas_found']}")
        if results.get("output_image"):
            console.print(
                f"[green]Change analysis image saved to: {results['output_image']}[/green]"
            )
    except Exception as e:
        console.print(f"[bold red]An error occurred during change detection:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    imint_app()