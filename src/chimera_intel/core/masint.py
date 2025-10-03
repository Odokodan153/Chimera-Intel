import click
from pathlib import Path
import json
from scapy.all import rdpcap, RadioTap, Dot11
import librosa
import numpy as np
from PIL import Image
import requests
from io import BytesIO

# Import the new schemas
from .schemas import MASINTResult, RFEmission, AcousticSignature, ThermalSignature


def analyze_rf_from_pcap(pcap_file: Path) -> list[RFEmission]:
    """
    Analyzes a PCAP file to identify and characterize RF emissions.
    This function uses Scapy to parse 802.11 packets and extract RadioTap headers.
    """
    emissions = []
    try:
        packets = rdpcap(str(pcap_file))
        for packet in packets:
            if packet.haslayer(RadioTap) and packet.haslayer(Dot11):
                radiotap = packet.getlayer(RadioTap)
                # Not all RadioTap headers have all fields, so we need to check
                if hasattr(radiotap, "dbm_antsignal") and hasattr(
                    radiotap, "ChannelFrequency"
                ):
                    power_dbm = radiotap.dbm_antsignal
                    frequency_mhz = radiotap.ChannelFrequency
                    # Simple guess based on frequency band
                    device_guess = (
                        "Wi-Fi (2.4GHz)"
                        if 2400 <= frequency_mhz <= 2500
                        else "Wi-Fi (5GHz)"
                    )
                    emissions.append(
                        RFEmission(
                            frequency_mhz=frequency_mhz,
                            power_dbm=power_dbm,
                            modulation_type="802.11",
                            source_device_guess=device_guess,
                            confidence="High",
                        )
                    )
    except Exception as e:
        click.echo(f"Error processing PCAP file: {e}", err=True)
    return emissions


def analyze_acoustic_from_media(media_file: Path) -> list[AcousticSignature]:
    """
    Analyzes an audio or video file to identify unique acoustic signatures
    using Librosa for feature extraction.
    """
    signatures = []
    try:
        y, sr = librosa.load(media_file)
        # Perform a Fast Fourier Transform (FFT)
        fft = np.fft.fft(y)
        magnitude = np.abs(fft)
        frequency = np.fft.fftfreq(len(magnitude), 1 / sr)
        # Find the peak frequency
        peak_frequency = frequency[np.argmax(magnitude)]
        # Convert magnitude to decibels
        db_level = librosa.amplitude_to_db(magnitude, ref=np.max)[
            np.argmax(magnitude)
        ]
        signature_type = (
            "Power Grid Hum"
            if 58 <= abs(peak_frequency) <= 62
            else "Generic Acoustic Noise"
        )
        signatures.append(
            AcousticSignature(
                dominant_frequency_hz=abs(peak_frequency),
                decibel_level=float(db_level),
                signature_type=signature_type,
            )
        )
    except Exception as e:
        click.echo(f"Error processing media file: {e}", err=True)
    return signatures


def analyze_thermal_from_imagery(image_url: str) -> list[ThermalSignature]:
    """
    Analyzes an image URL to simulate identifying thermal signatures.
    NOTE: This is a conceptual implementation. True thermal analysis requires
    multi-spectral imagery (e.g., from Landsat or a commercial provider).
    This function uses pixel brightness as a proxy for temperature.
    """
    signatures = []
    try:
        response = requests.get(image_url)
        img = Image.open(BytesIO(response.content)).convert("L")  # Convert to grayscale
        img_array = np.array(img)
        # Use the brightest pixel as a proxy for the highest temperature
        max_brightness = np.max(img_array)
        # Scale brightness (0-255) to a plausible temperature range (e.g., 0-100 C)
        scaled_temp = (max_brightness / 255) * 100
        signatures.append(
            ThermalSignature(
                max_temperature_celsius=scaled_temp,
                dominant_infrared_band="Simulated (from visible spectrum)",
                activity_level_guess="Medium",
                source_object_guess="Brightest object in image",
            )
        )
    except Exception as e:
        click.echo(f"Error processing image from URL: {e}", err=True)
    return signatures


@click.group("masint")
def masint_cli():
    """📡 MASINT Core for analyzing physical signatures."""
    pass


@masint_cli.command("analyze-rf")
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
def analyze_rf(pcap_file):
    """Analyze RF signatures from a PCAP file."""
    result = MASINTResult(target_identifier=pcap_file)
    result.rf_emissions = analyze_rf_from_pcap(Path(pcap_file))
    click.echo(result.model_dump_json(indent=4))


@masint_cli.command("analyze-acoustic")
@click.argument("media_file", type=click.Path(exists=True, dir_okay=False))
def analyze_acoustic(media_file):
    """Analyze acoustic signatures from a media file."""
    result = MASINTResult(target_identifier=media_file)
    result.acoustic_signatures = analyze_acoustic_from_media(Path(media_file))
    click.echo(result.model_dump_json(indent=4))


@masint_cli.command("analyze-thermal")
@click.argument("image_url", type=str)
def analyze_thermal(image_url):
    """(Simulated) Analyze thermal signatures from an image URL."""
    result = MASINTResult(target_identifier=image_url)
    result.thermal_signatures = analyze_thermal_from_imagery(image_url)
    click.echo(result.model_dump_json(indent=4))


if __name__ == "__main__":
    masint_cli()