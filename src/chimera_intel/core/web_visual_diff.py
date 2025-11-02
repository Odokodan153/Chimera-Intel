"""
Web Difference Visualizer Module for Chimera Intel.

Enhances the 'diff' module by visually comparing screenshots
from 'web' or 'page_monitor' scans.
"""

import typer
import logging
import sys
from typing import Optional, Tuple, Dict, Any
from pydantic import BaseModel
from chimera_intel.core.schemas import BaseChimeraResult
from chimera_intel.core.utils import console
from chimera_intel.core.database import get_db_connection
from chimera_intel.core.project_manager import resolve_target

# This module requires the 'pillow' library
try:
    from PIL import Image, ImageChops, ImageEnhance
except ImportError:
    print(
        "Error: 'pillow' library not found. Please install it: pip install pillow",
        file=sys.stderr,
    )
    sys.exit(1)


logger = logging.getLogger(__name__)


class VisualDiffResult(BaseChimeraResult):
    target: str
    module: str
    previous_scan_image: str
    latest_scan_image: str
    diff_output_path: str
    pixels_changed: int = 0


def get_last_two_scans_with_screenshots(
    target: str, module: str
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Retrieves the two most recent scans for a specific target and module
    that *must* contain a 'screenshot_path' in their scan_data.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Use JSON operators to filter for records containing the key
        cursor.execute(
            """
            SELECT scan_data, timestamp FROM scans
            WHERE target = %s AND module = %s AND scan_data ? 'screenshot_path'
            ORDER BY timestamp DESC
            LIMIT 2
            """,
            (target, module),
        )
        records = cursor.fetchall()
        conn.close()
        if len(records) < 2:
            return None, None
        # records[0] is latest, records[1] is previous
        return records[0][0], records[1][0]
    except Exception as e:
        logger.error("Database error fetching scans for '%s': %s", target, e)
        return None, None


def create_visual_diff(
    target: str,
    module: str,
    output_path: str,
    previous_scan: Dict[str, Any],
    latest_scan: Dict[str, Any],
) -> VisualDiffResult:
    """
    Compares two screenshot images and saves a visual diff.
    """
    prev_img_path = previous_scan.get("screenshot_path")
    latest_img_path = latest_scan.get("screenshot_path")

    if not prev_img_path or not latest_img_path:
        return VisualDiffResult(
            target=target,
            module=module,
            error="One or both scans are missing 'screenshot_path'.",
        )

    try:
        with Image.open(prev_img_path) as img1, Image.open(
            latest_img_path
        ) as img2:
            if img1.size != img2.size or img1.mode != img2.mode:
                logger.warning(
                    "Images have different sizes or modes. Resizing for diff."
                )
                img2 = img2.resize(img1.size, Image.LANCZOS)
                if img1.mode != img2.mode:
                    img2 = img2.convert(img1.mode)

            # Create a difference image
            diff = ImageChops.difference(img1, img2)

            # Enhance the diff to make changes more visible
            enhancer = ImageEnhance.Brightness(diff)
            diff = enhancer.enhance(10)  # Greatly increase brightness of diffs

            # Calculate the number of changed pixels
            stat = diff.getextrema()
            # For RGB images, stat is ((min_r, max_r), (min_g, max_g), (min_b, max_b))
            pixels_changed = sum(
                s[1] for s in stat
            )  # Sum of max values of each channel

            # Save the diff
            diff.save(output_path)

            return VisualDiffResult(
                target=target,
                module=module,
                previous_scan_image=prev_img_path,
                latest_scan_image=latest_img_path,
                diff_output_path=output_path,
                pixels_changed=pixels_changed,
            )
    except Exception as e:
        logger.error(f"Failed to create visual diff: {e}")
        return VisualDiffResult(
            target=target, module=module, error=f"Image processing error: {e}"
        )


web_visual_diff_app = typer.Typer(
    name="visual-diff",
    help="Visually compares web page screenshots from the 'diff' module.",
)


@web_visual_diff_app.command("run")
def run_visual_diff(
    output_file: str = typer.Option(
        ...,
        "--output",
        "-o",
        help="Path to save the resulting difference image (e.g., 'diff.png').",
    ),
    module: str = typer.Option(
        "page_monitor",
        help="The scan module to compare (must save 'screenshot_path').",
    ),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="The target to compare. Uses active project if not provided.",
    ),
):
    """
    Compares the last two web page screenshots for a target.
    """
    try:
        target_name = resolve_target(target)
    except typer.Exit as e:
        raise typer.Exit(code=e.exit_code)

    console.print(
        f"\n--- [bold]Visual Diff for {target_name} (Module: {module})[/bold] ---\n"
    )
    latest, previous = get_last_two_scans_with_screenshots(target_name, module)

    if previous is None or latest is None:
        console.print(
            "[bold yellow]Not enough historical screenshot data to perform a comparison.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    console.print(
        f"Comparing '{latest.get('screenshot_path')}' (new) vs. '{previous.get('screenshot_path')}' (old)"
    )

    result_model = create_visual_diff(
        target_name, module, output_file, previous, latest
    )

    if result_model.error:
        console.print(f"[bold red]Error:[/bold red] {result_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"[bold green]Success![/bold green] Visual diff saved to: {result_model.diff_output_path}"
    )
    console.print(f"Pixels changed (sum of max channel values): {result_model.pixels_changed}")