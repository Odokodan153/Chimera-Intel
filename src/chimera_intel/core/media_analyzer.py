"""
Module for Image, Video, and Audio Intelligence (IMINT/VIDINT).

Provides tools to perform reverse image searches and transcribe audio files.
"""

import typer
import logging
import asyncio 
from typing import Optional, List
import speech_recognition as sr  # type: ignore
from .schemas import (
    ReverseImageSearchResult,
    ReverseImageMatch,
    MediaAnalysisResult,
    MediaTranscript,
)
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import sync_client
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)


async def reverse_image_search(image_path: str) -> ReverseImageSearchResult:
    """
    Performs a reverse image search using Google Images.
    NOTE: This is a web scraper and may break if Google changes its HTML structure.

    Args:
        image_path (str): The local path to the image file.

    Returns:
        ReverseImageSearchResult: A Pydantic model with the search results.
    """
    logger.info(f"Performing reverse image search for {image_path}")
    matches: List[ReverseImageMatch] = []
    search_url = "http://www.google.com/searchbyimage/upload"

    try:
        with open(image_path, "rb") as f:
            multipart = {"encoded_image": (image_path, f.read(), "image/jpeg")}

            # Make a POST request to upload the image

            response = sync_client.post(
                search_url, files=multipart, follow_redirects=False
            )

            # Get the redirect URL

            redirect_url = response.headers.get("Location")

            if not redirect_url:
                raise Exception("Could not get redirect URL from Google.")
            # Follow the redirect to get the search results

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            search_response = sync_client.get(redirect_url, headers=headers)
            search_response.raise_for_status()

            # Parse the search results

            soup = BeautifulSoup(search_response.text, "html.parser")

            for g in soup.find_all("div", class_="g"):
                a_tag = g.find("a")
                h3_tag = g.find("h3")
                if a_tag and h3_tag:
                    link = a_tag.get("href")
                    title = h3_tag.text
                    matches.append(
                        ReverseImageMatch(
                            page_url=link,
                            page_title=title,
                            image_url="",  # Not easily available from search results page
                            source_engine="Google Images",
                        )
                    )
    except Exception as e:
        logger.error(f"Failed to perform reverse image search for {image_path}: {e}")
        return ReverseImageSearchResult(
            source_image_path=image_path,
            matches_found=0,
            matches=[],
            error=f"An error occurred during reverse image search: {e}",
        )
    return ReverseImageSearchResult(
        source_image_path=image_path, matches_found=len(matches), matches=matches
    )


def transcribe_audio_file(file_path: str) -> MediaAnalysisResult:
    """
    Transcribes an audio file to text using the SpeechRecognition library with Whisper.

    Args:
        file_path (str): The path to the audio file (e.g., .wav, .mp3).

    Returns:
        MediaAnalysisResult: A Pydantic model with the transcript.
    """
    logger.info(f"Transcribing audio file: {file_path}")
    recognizer = sr.Recognizer()

    try:
        with sr.AudioFile(file_path) as source:
            audio_data = recognizer.record(source)
        # Recognize speech using Whisper's offline model

        result = recognizer.recognize_whisper(audio_data, language="english")

        transcript = MediaTranscript(
            language="english",
            text=result,
            confidence=1.0,  # Whisper recognizer in this library doesn't provide confidence score
        )
        return MediaAnalysisResult(
            file_path=file_path, media_type="Audio", transcript=transcript
        )
    except Exception as e:
        logger.error(f"Failed to transcribe audio file {file_path}: {e}")
        return MediaAnalysisResult(
            file_path=file_path,
            media_type="Audio",  # <-- This is already correct
            error=f"An error occurred during transcription: {e}",
        )


# --- Typer CLI Application ---


media_app = typer.Typer()


@media_app.command("reverse-search")
def run_reverse_image_search(  # <-- CHANGED: Removed 'async'
    file_path: str = typer.Argument(..., help="Path to the image file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Performs a reverse image search to find where an image appears online.
    """
    # --- CHANGED: Use asyncio.run() to call the async function ---
    with console.status(
        f"[bold cyan]Performing reverse image search on {file_path}...[/bold cyan]"
    ):
        results_model = asyncio.run(reverse_image_search(file_path))

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=file_path, module="media_reverse_image_search", data=results_dict
    )


@media_app.command("transcribe")
def run_audio_transcription(
    file_path: str = typer.Argument(..., help="Path to the audio file."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Transcribes an audio file to text using an offline speech recognition model.
    """
    with console.status(
        f"[bold cyan]Transcribing audio from {file_path}... (this may take a moment)[/bold cyan]"
    ):
        results_model = transcribe_audio_file(file_path)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=file_path, module="media_transcription", data=results_dict)


if __name__ == "__main__":
    media_app()
