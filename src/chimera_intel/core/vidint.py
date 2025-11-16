"""
Module for Video Intelligence (VIDINT).

Provides tools to analyze video files, extract metadata, save frames,
and perform content analysis (object detection).
"""

import typer
import os
from rich.console import Console
import cv2
import numpy as np
from typing import Dict
try:
    from .imint import perform_object_detection
    IMINT_AVAILABLE = True
except ImportError:
    IMINT_AVAILABLE = False
    def perform_object_detection(image_path: str) -> dict:
        raise ImportError("IMINT module or its dependencies are not available.")

console = Console()

vidint_app = typer.Typer(
    name="vidint",
    help="Video Intelligence (VIDINT) operations.",
)


def run_motion_detection(file_path: str, threshold: int = 30):
    """
    Detects motion in a video file by comparing consecutive frames.
    """
    console.print(f"Detecting motion in {file_path}...")
    vid = cv2.VideoCapture(file_path)
    if not vid.isOpened():
        console.print(
            "[bold red]Error:[/bold red] Could not open video file for motion detection."
        )
        return
    try:
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
    finally:
        vid.release()
    if motion_events > 5:  # Simple threshold to reduce noise
        console.print(
            f"[bold yellow]Significant motion detected in {motion_events} frames.[/bold yellow]"
        )
    else:
        console.print("[green]No significant motion detected.[/green]")


# +++ NEW FUNCTION (POINT 2) +++
def analyze_video_content(
    file_path: str, temp_dir: str, sample_rate_sec: int = 5
) -> Dict[str, int]:
    """
    Performs object detection on video frames by sampling the video.
    """
    if not IMINT_AVAILABLE:
        console.print("[bold red]Error:[/bold red] IMINT module 'perform_object_detection' is not available.")
        return {}

    console.print(f"Analyzing video content (sampling 1 frame every {sample_rate_sec}s)...")
    vid = cv2.VideoCapture(file_path)
    if not vid.isOpened():
        console.print("[bold red]Error:[/bold red] Could not open video file for content analysis.")
        return {}

    fps = vid.get(cv2.CAP_PROP_FPS)
    frame_interval = int(fps * sample_rate_sec)
    frame_count = int(vid.get(cv2.CAP_PROP_FRAME_COUNT))
    
    if frame_interval == 0:
        frame_interval = int(fps) # Default to 1s if calculation fails
    if frame_interval == 0:
        frame_interval = 1 # Failsafe

    aggregated_objects: Dict[str, int] = {}
    temp_frame_file = os.path.join(temp_dir, "temp_vidint_frame.jpg")

    try:
        for frame_num in range(0, frame_count, frame_interval):
            vid.set(cv2.CAP_PROP_POS_FRAMES, frame_num)
            success, image = vid.read()
            if success:
                # Save the frame as a temporary image
                cv2.imwrite(temp_frame_file, image)
                
                # Run object detection on the saved frame
                try:
                    detected_objects = perform_object_detection(temp_frame_file)
                    for obj, count in detected_objects.items():
                        aggregated_objects[obj] = aggregated_objects.get(obj, 0) + count
                except Exception as e:
                    console.print(f"[yellow]Warning: Frame analysis failed: {e}[/yellow]")
        
        # Clean up the temp frame
        if os.path.exists(temp_frame_file):
            os.remove(temp_frame_file)

    finally:
        vid.release()

    return aggregated_objects


@vidint_app.command(help="Analyze a video file and extract metadata or frames.")
def analyze(
    file_path: str = typer.Argument(..., help="Path to the video file to analyze."),
    extract_frames: int = typer.Option(
        None,
        "--extract-frames",
        "-f",
        help="Extract one frame every N seconds and save as JPG.",
    ),
    output_dir: str = typer.Option(
        "video_frames", "--output-dir", "-d", help="Directory to save extracted frames."
    ),
    detect_motion: bool = typer.Option(
        False,
        "--detect-motion",
        help="Detect motion in the video.",
    ),
    # +++ NEW CLI OPTION (POINT 2) +++
    analyze_content: bool = typer.Option(
        False,
        "--analyze-content",
        help="Perform object detection on video frames.",
    ),
    content_sample_rate: int = typer.Option(
        5,
        "--sample-rate",
        help="Seconds between frames for content analysis."
    )
):
    """
    Analyzes a video file to extract key metadata, save frames,
    detect motion, or analyze content for objects.
    """
    console.print(f"Analyzing video file: {file_path}")
    if not os.path.exists(file_path):
        console.print(
            f"[bold red]Error:[/bold red] Video file not found at '{file_path}'"
        )
        raise typer.Exit(code=1)
    
    # Ensure output_dir exists for all operations that need it
    if extract_frames or analyze_content:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    vid = None
    try:
        vid = cv2.VideoCapture(file_path)
        if not vid.isOpened():
            console.print("[bold red]Error:[/bold red] Could not open video file.")
            raise typer.Exit(code=1)

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

        if extract_frames:
            frame_interval = int(fps * extract_frames)
            if frame_interval == 0: frame_interval = 1 # Failsafe
            saved_count = 0
            vid.set(cv2.CAP_PROP_POS_FRAMES, 0)
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

        # --- MODIFIED: Release vid before calling other functions ---
        if vid and vid.isOpened():
            vid.release()
            vid = None # Set to None so finally: doesn't try to release again

        if detect_motion:
            run_motion_detection(file_path)
        
        # +++ NEW CONTENT ANALYSIS (POINT 2) +++
        if analyze_content:
            objects_found = analyze_video_content(file_path, output_dir, content_sample_rate)
            console.print("\n--- [bold green]Video Content Analysis[/bold green] ---")
            if objects_found:
                console.print("Aggregated objects detected in video:")
                for obj, count in objects_found.items():
                    console.print(f"- {obj}: {count} instance(s)")
            else:
                console.print("No objects detected.")
            console.print("-------------------------------")

    except Exception as e:
        console.print(
            f"[bold red]An error occurred during video analysis:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
    finally:
        if vid and vid.isOpened():
            vid.release()

if __name__ == "__main__":
    vidint_app()