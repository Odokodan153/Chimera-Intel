import typer
import numpy as np
import cv2
from rich.console import Console
from rich.table import Table
from scapy.all import rdpcap
import importlib

# Conditional import for librosa, as it's a heavy dependency


class LibrosaPlaceholder:
    def __getattr__(self, name):
        def method(*args, **kwargs):
            raise ImportError(
                "librosa is not installed. Please run 'pip install librosa' to use this feature."
            )

        return method


try:
    librosa = importlib.import_module("librosa")
except ImportError:
    librosa = LibrosaPlaceholder()
app = typer.Typer(
    no_args_is_help=True, help="Measurement and Signature Intelligence (MASINT) tools."
)
console = Console()


class Masint:
    """
    Handles MASINT tasks by analyzing unique signatures from various sources.
    """

    def analyze_rf_pcap(self, pcap_path: str):
        """
        Analyzes a PCAP file to generate a basic RF signature of the traffic.
        This simplified example creates a signature based on packet size distribution.
        """
        try:
            packets = rdpcap(pcap_path)
            sizes = [len(p) for p in packets]
            if not sizes:
                console.print(
                    "[yellow]PCAP file is empty or could not be read.[/yellow]"
                )
                return None
            hist, _ = np.histogram(sizes, bins=10, range=(0, 1500))
            signature = {"packet_count": len(sizes), "size_histogram": hist.tolist()}
            return signature
        except Exception as e:
            console.print(f"[bold red]Error processing PCAP file: {e}[/bold red]")
            return None

    def analyze_acoustic_signature(self, audio_path: str):
        """
        Analyzes an audio file to extract its acoustic signature using MFCCs.
        """
        if isinstance(librosa, LibrosaPlaceholder):
            console.print(
                "[bold red]librosa library not installed. Please run 'pip install librosa' to use this feature.[/bold red]"
            )
            return None
        try:
            y, sr = librosa.load(audio_path)
            mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
            # A simplified signature is the mean of each MFCC over time

            signature = np.mean(mfccs, axis=1)
            return signature.tolist()
        except Exception as e:
            console.print(f"[bold red]Error processing audio file: {e}[/bold red]")
            return None

    def analyze_thermal_image(self, image_path: str, threshold: int = 200):
        """
        Analyzes a thermal (grayscale) image to find hotspots.
        """
        try:
            image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
            if image is None:
                console.print("[bold red]Could not read image file.[/bold red]")
                return None
            _, thresh = cv2.threshold(image, threshold, 255, cv2.THRESH_BINARY)
            contours, _ = cv2.findContours(
                thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
            )

            hotspots = []
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                hotspots.append({"x": x, "y": y, "width": w, "height": h})
            return hotspots
        except Exception as e:
            console.print(f"[bold red]Error processing image file: {e}[/bold red]")
            return None


@app.command(name="rf-pcap")
def rf_pcap_analysis(
    pcap_path: str = typer.Argument(..., help="Path to the PCAP file to analyze."),
):
    """Analyzes RF signatures from a PCAP file."""
    masint = Masint()
    signature = masint.analyze_rf_pcap(pcap_path)
    if signature:
        console.print("[bold green]Generated RF Signature:[/bold green]")
        console.print_json(data=signature)


@app.command(name="acoustic")
def acoustic_analysis(
    audio_path: str = typer.Argument(
        ..., help="Path to the audio file (e.g., .wav, .mp3)."
    ),
):
    """Extracts an acoustic signature from an audio file."""
    masint = Masint()
    signature = masint.analyze_acoustic_signature(audio_path)
    if signature:
        console.print(
            "[bold green]Generated Acoustic Signature (MFCC Means):[/bold green]"
        )
        console.print(signature)


@app.command(name="thermal")
def thermal_analysis(
    image_path: str = typer.Argument(..., help="Path to the thermal image file."),
    threshold: int = typer.Option(
        200,
        "--threshold",
        "-t",
        help="Brightness threshold (0-255) to identify hotspots.",
    ),
):
    """Identifies hotspots in a thermal image."""
    masint = Masint()
    hotspots = masint.analyze_thermal_image(image_path, threshold)
    if hotspots:
        table = Table(title="Detected Thermal Hotspots")
        table.add_column("X", style="cyan")
        table.add_column("Y", style="cyan")
        table.add_column("Width", style="magenta")
        table.add_column("Height", style="magenta")
        for spot in hotspots:
            table.add_row(
                str(spot["x"]), str(spot["y"]), str(spot["width"]), str(spot["height"])
            )
        console.print(table)
    else:
        console.print("[yellow]No hotspots detected at the given threshold.[/yellow]")


if __name__ == "__main__":
    app()
