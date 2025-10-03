"""
Module for Video Intelligence (VIDINT).

Provides tools to analyze video files, extract metadata, and save frames
for further analysis.
"""

import typer
import os
from typing import Optional
from rich.console import Console
import cv2

console = Console()

vidint_app = typer.Typer(
    name="vidint",
    help="Video Intelligence (VIDINT) operations.",
)


@vidint_app.command(
    name="analyze-video", help="Analyze a video file and extract metadata or frames."
)
def analyze_video(
    file_path: str = typer.Argument(..., help="Path to the video file to analyze."),
    extract_frames: Optional[int] = typer.Option(
        None,
        "--extract-frames",
        "-f",
        help="Extract one frame every N seconds and save as JPG.",
    ),
    output_dir: str = typer.Option(
        "video_frames", "--output-dir", "-d", help="Directory to save extracted frames."
    ),
):
    """
    Analyzes a video file to extract key metadata and optionally saves
    frames for further analysis.
    """
    console.print(f"Analyzing video file: {file_path}")
    if not os.path.exists(file_path):
        console.print(
            f"[bold red]Error:[/bold red] Video file not found at '{file_path}'"
        )
        raise typer.Exit(code=1)
    try:
        vid = cv2.VideoCapture(file_path)
        if not vid.isOpened():
            console.print("[bold red]Error:[/bold red] Could not open video file.")
            raise typer.Exit(code=1)
        # Extract metadata

        frame_count = int(vid.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = vid.get(cv2.CAP_PROP_FPS)
        duration = frame_count / fps if fps > 0 else 0
        width = int(vid.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(vid.get(cv2.CAP_PROP_FRAME_HEIGHT))

        console.print("\n--- [bold green]Video Metadata[/bold green] ---")
        console.print(f"- Resolution: {width}x{height}")
        console.print(f"- Frame Rate: {fps:.2f} FPS")
        console.print(f"- Duration: {duration:.2f} seconds")
        console.print(f"- Total Frames: {frame_count}")
        console.print("--------------------------")

        # Extract frames if requested

        if extract_frames:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            frame_interval = int(fps * extract_frames)
            saved_count = 0
            for i in range(0, frame_count, frame_interval):
                vid.set(cv2.CAP_PROP_POS_FRAMES, i)
                success, image = vid.read()
                if success:
                    frame_filename = os.path.join(
                        output_dir, f"frame_{saved_count}.jpg"
                    )
                    cv2.imwrite(frame_filename, image)
                    saved_count += 1
            console.print(
                f"\nSuccessfully extracted {saved_count} frames to '{output_dir}'."
            )
        vid.release()
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during video analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    vidint_app()
