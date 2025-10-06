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
import numpy as np

console = Console()

vidint_app = typer.Typer(
    name="vidint",
    help="Video Intelligence (VIDINT) operations.",
)


def detect_motion(file_path: str, threshold: int = 30):
    """
    Detects motion in a video file by comparing consecutive frames.
    """
    console.print(f"Detecting motion in {file_path}...")
    vid = cv2.VideoCapture(file_path)
    if not vid.isOpened():
        return
    _, frame1 = vid.read()
    if frame1 is None:
        return
    gray1 = cv2.cvtColor(frame1, cv2.COLOR_BGR2GRAY)
    gray1 = cv2.GaussianBlur(gray1, (21, 21), 0)

    motion_events = 0
    kernel = np.ones((5, 5), np.uint8)
    while True:
        ret, frame2 = vid.read()
        if not ret:
            break
        gray2 = cv2.cvtColor(frame2, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.GaussianBlur(gray2, (21, 21), 0)

        frame_delta = cv2.absdiff(gray1, gray2)
        thresh = cv2.threshold(frame_delta, threshold, 255, cv2.THRESH_BINARY)[1]
        thresh = cv2.dilate(thresh, kernel, iterations=2)

        contours, _ = cv2.findContours(
            thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )

        if contours:
            motion_events += 1
        gray1 = gray2  # Move to the next frame
    vid.release()
    if motion_events > 5:  # Simple threshold to reduce noise
        console.print(
            f"[bold yellow]Significant motion detected in {motion_events} frames.[/bold yellow]"
        )
    else:
        console.print("[green]No significant motion detected.[/green]")


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
    detect_motion_flag: bool = typer.Option(
        False,
        "--detect-motion",
        help="Detect motion in the video.",
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
        if detect_motion_flag:
            detect_motion(file_path)
        vid.release()
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during video analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    vidint_app()
