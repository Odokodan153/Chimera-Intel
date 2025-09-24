# src/chimera_intel/core/podcast_osint.py


import typer
import logging
import feedparser  # type: ignore
import os
from typing import Optional
from rich.markdown import Markdown

from .schemas import (
    PodcastInfoResult,
    PodcastEpisode,
    PodcastSearchResult,
    PodcastAnalysisResult,
)
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import sync_client
from .media_analyzer import transcribe_audio_file
from .ai_core import generate_swot_from_data  # Re-using for general AI generation
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


def find_podcast_info(feed_url: str) -> PodcastInfoResult:
    """
    Parses a podcast's RSS feed to extract its details and episode list.

    Args:
        feed_url (str): The URL of the podcast's RSS feed.

    Returns:
        PodcastInfoResult: A Pydantic model with the podcast's information.
    """
    logger.info(f"Parsing podcast feed from: {feed_url}")
    try:
        feed = feedparser.parse(feed_url)
        if feed.bozo:
            raise ValueError(f"Feed is malformed. Reason: {feed.bozo_exception}")
        episodes = []
        for entry in feed.entries:
            audio_url = next(
                (
                    link.get("href")
                    for link in entry.get("links", [])
                    if link.get("rel") == "enclosure"
                ),
                None,
            )

            episode_data = {
                "title": entry.get("title"),
                "published": entry.get("published"),
                "summary": entry.get("summary"),
                "audio_url": audio_url,
            }
            episodes.append(PodcastEpisode.model_validate(episode_data))
        return PodcastInfoResult(
            feed_url=feed_url,
            title=feed.feed.get("title"),
            author=feed.feed.get("author"),
            episodes=episodes,
        )
    except Exception as e:
        logger.error(f"Failed to parse podcast feed at {feed_url}: {e}")
        return PodcastInfoResult(feed_url=feed_url, error=str(e))


def search_in_podcast_episode(audio_url: str, keyword: str) -> PodcastSearchResult:
    """
    Downloads, transcribes, and searches a single podcast episode for a keyword.

    Args:
        audio_url (str): The direct URL to the episode's audio file.
        keyword (str): The keyword to search for.

    Returns:
        PodcastSearchResult: A Pydantic model with the search results.
    """
    logger.info(f"Searching for '{keyword}' in episode from {audio_url}")
    temp_dir = "temp_audio"
    os.makedirs(temp_dir, exist_ok=True)
    file_name = audio_url.split("/")[-1].split("?")[0]
    file_path = os.path.join(temp_dir, file_name)

    try:
        # Download the audio file

        with sync_client.stream("GET", audio_url, follow_redirects=True) as response:
            response.raise_for_status()
            with open(file_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)
        # Transcribe the audio file

        transcription_result = transcribe_audio_file(file_path)
        if transcription_result.error or not transcription_result.transcript:
            raise ValueError(transcription_result.error or "Transcription failed.")
        transcript_text = transcription_result.transcript.text

        # Search for the keyword

        is_found = keyword.lower() in transcript_text.lower()
        snippet = ""
        if is_found:
            index = transcript_text.lower().find(keyword.lower())
            start = max(0, index - 50)
            end = min(len(transcript_text), index + 50)
            snippet = f"...{transcript_text[start:end]}..."
        return PodcastSearchResult(
            episode_audio_url=audio_url,
            keyword=keyword,
            is_found=is_found,
            transcript_snippet=snippet,
        )
    except Exception as e:
        logger.error(f"Failed to search in podcast episode {audio_url}: {e}")
        return PodcastSearchResult(
            episode_audio_url=audio_url, keyword=keyword, is_found=False, error=str(e)
        )
    finally:
        # Clean up the downloaded file

        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)


def analyze_podcast_episode(audio_url: str) -> PodcastAnalysisResult:
    """
    Downloads, transcribes, and generates an AI summary of a podcast episode.
    """
    logger.info(f"Starting AI analysis for episode from {audio_url}")
    temp_dir = "temp_audio"
    os.makedirs(temp_dir, exist_ok=True)
    file_name = audio_url.split("/")[-1].split("?")[0]
    file_path = os.path.join(temp_dir, file_name)

    try:
        # 1. Download the audio file

        with sync_client.stream("GET", audio_url, follow_redirects=True) as response:
            response.raise_for_status()
            with open(file_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)
        # 2. Transcribe the audio file

        transcription_result = transcribe_audio_file(file_path)
        if transcription_result.error or not transcription_result.transcript:
            raise ValueError(transcription_result.error or "Transcription failed.")
        transcript_text = transcription_result.transcript.text

        # 3. Generate AI Analysis

        api_key = API_KEYS.google_api_key
        if not api_key:
            raise ValueError("Google API key not found. Cannot perform analysis.")
        prompt = f"""
        As an expert analyst, your task is to analyze the following podcast transcript.
        Present the output in Markdown format.

        1.  **Executive Summary:** Provide a concise, one-paragraph summary of the entire episode.
        2.  **Key Topics Discussed:** List the 3-5 main topics or themes discussed in a bulleted list.
        3.  **Overall Sentiment:** Describe the overall tone and sentiment of the conversation (e.g., positive, critical, technical, humorous).

        **Podcast Transcript:**
        ---
        {transcript_text[:15000]} 
        """  # Truncate to avoid exceeding model token limits

        # We re-use the generic text generation function from the AI core

        ai_result = generate_swot_from_data(prompt, api_key)
        if ai_result.error:
            raise ValueError(f"AI analysis failed: {ai_result.error}")
        return PodcastAnalysisResult(
            episode_audio_url=audio_url, analysis_text=ai_result.analysis_text
        )
    except Exception as e:
        logger.error(f"Failed to analyze podcast episode {audio_url}: {e}")
        return PodcastAnalysisResult(
            episode_audio_url=audio_url, analysis_text="", error=str(e)
        )
    finally:
        # Clean up

        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
            os.rmdir(temp_dir)


# --- Typer CLI Application ---


podcast_app = typer.Typer()


@podcast_app.command("info")
def run_podcast_info(
    feed_url: str = typer.Argument(..., help="The URL of the podcast's RSS feed."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Gets information and episode list for a podcast from its RSS feed."""
    with console.status(f"[bold cyan]Fetching info from {feed_url}...[/bold cyan]"):
        results = find_podcast_info(feed_url)
    results_dict = results.model_dump(exclude_none=True, by_alias=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=feed_url, module="podcast_info", data=results_dict)


@podcast_app.command("search")
def run_podcast_search(
    audio_url: str = typer.Argument(
        ..., help="The direct URL to the episode's audio file (.mp3, .wav, etc.)."
    ),
    keyword: str = typer.Option(
        ..., "--keyword", "-k", help="The keyword to search for in the episode."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches for a keyword within a single podcast episode by transcribing it."""
    console.print(f"[cyan]Starting search for '{keyword}' in episode...[/cyan]")
    console.print(
        "[yellow]Note: Downloading and transcribing may take a few minutes.[/yellow]"
    )

    results = search_in_podcast_episode(audio_url, keyword)

    results_dict = results.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=audio_url, module="podcast_search", data=results_dict)


@podcast_app.command("analyze")
def run_podcast_analysis(
    audio_url: str = typer.Argument(
        ..., help="The direct URL to the episode's audio file."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the full analysis object to a JSON file."
    ),
):
    """Generates an AI-powered summary and analysis of a podcast episode."""
    console.print(f"[cyan]Starting analysis for episode at {audio_url}...[/cyan]")
    console.print(
        "[yellow]Note: This involves downloading and transcribing, which may take several minutes.[/yellow]"
    )

    with console.status("[bold cyan]AI is processing the episode...[/bold cyan]"):
        results = analyze_podcast_episode(audio_url)
    if results.error:
        console.print(f"[bold red]Error during analysis:[/bold red] {results.error}")
        raise typer.Exit(code=1)
    console.print("\n--- [bold green]Podcast Episode Analysis[/bold green] ---\n")
    console.print(Markdown(results.analysis_text))

    if output_file:
        results_dict = results.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(target=audio_url, module="podcast_analysis", data=results_dict)
