"""
Module for Image & Video Intelligence (IMINT/VIDINT).

Provides tools to extract metadata from images, perform reverse image searches,
and (in the future) run object and facial recognition.
"""

import typer
import logging
from typing import Optional, Dict, Any
from PIL import Image
from PIL.ExifTags import TAGS
from .schemas import ImageAnalysisResult, ExifData
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)


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


imint_app = typer.Typer()


@imint_app.command("analyze-image")
def run_image_analysis(
    file_path: str = typer.Argument(..., help="Path to the image file to analyze."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Extracts and analyzes metadata from an image file.
    """
    results_model = analyze_image_metadata(file_path)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=file_path, module="imint_analysis", data=results_dict)
