"""
Active Radio Frequency Intelligence (RFINT) tools.
Requires specialized hardware (SDR, Wi-Fi/BLE adapters).
"""

import typer
import asyncio
import json
import logging
from typing import List, Dict, Optional, Set
from rich.console import Console
from chimera_intel.core.utils import save_or_print_results
from chimera_intel.core.database import save_scan_to_db
from .schemas import (
    BLEDevice,
    WiFiDevice,
    RFSignal,
    RFScanReport,
)
try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice as BleakDeviceImpl
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print(
        "Bleak not installed. Live Bluetooth (BLE) scanning will not be available. "
        "Please run: pip install bleak"
    )
    BleakScanner = None  # type: ignore
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
except ImportError:
    print(
        "Scapy not installed. Live Wi-Fi scanning will not be available. "
        "Please run: pip install scapy"
    )
    sniff = None  # type: ignore
try:
    from rtlsdr import RtlSdr
except ImportError:
    print(
        "rtlsdr (pyrtlsdr) not installed. Active SDR scanning will not be available. "
        "Please run: pip install pyrtlsdr"
    )
    RtlSdr = None  # type: ignore
try:
    import numpy as np
except ImportError:
    print(
        "Numpy not installed. SDR scanning will not be available. "
        "Please run: pip install numpy"
    )
    np = None  # type: ignore


# --- Rich Console ---
console = Console(width=200)
logger = logging.getLogger(__name__)

# --- Global Dictionaries for Live Scapy Scan ---
# We use globals here because the Scapy `sniff` callback
# cannot easily be passed a state object.
_wifi_aps: Dict[str, WiFiDevice] = {}
_wifi_clients: Dict[str, WiFiDevice] = {}


# --- Bluetooth (BLE) Scanning ---

async def scan_ble_devices(scan_duration: int = 10) -> List[BLEDevice]:
    """
    Scans for nearby Bluetooth Low Energy (BLE) devices.
    """
    if BleakScanner is None:
        console.print("[bold red]Bleak library not found. BLE scan aborted.[/bold red]")
        return []
        
    console.print(f"[bold cyan]Starting BLE scan for {scan_duration} seconds...[/bold cyan]")
    devices_found: Dict[str, BLEDevice] = {}

    def detection_callback(device: BleakDeviceImpl, ad: AdvertisementData):
        if device.address not in devices_found:
            mfg_data_hex = {
                hex(k): v.hex() for k, v in ad.manufacturer_data.items()
            }
            
            devices_found[device.address] = BLEDevice(
                address=device.address,
                name=ad.local_name,
                rssi=ad.rssi,
                services=[str(uuid) for uuid in ad.service_uuids],
                manufacturer_data=mfg_data_hex
            )
        else:
            # Update RSSI
            devices_found[device.address].rssi = ad.rssi

    scanner = BleakScanner()
    scanner.register_detection_callback(detection_callback)
    
    await scanner.start()
    await asyncio.sleep(scan_duration)
    await scanner.stop()

    console.print(f"[bold green]BLE scan complete. Found {len(devices_found)} devices.[/bold green]")
    return list(devices_found.values())


# --- Live Wi-Fi Scanning ---

def _get_wifi_security(packet: Dot11Beacon) -> str:
    """Helper to parse Wi-Fi security from beacon packet."""
    crypto_set: Set[str] = set()
    # Check for RSN (WPA2/WPA3) - ID 48
    rsn_elt = packet.getlayer(Dot11Elt, ID=48)
    if rsn_elt:
        crypto_set.add("WPA2/3") # Cannot easily distinguish without deeper parsing

    # Check for WPA1 (Vendor Specific) - ID 221
    wpa_elt = packet.getlayer(Dot11Elt, ID=221)
    if wpa_elt and wpa_elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
        crypto_set.add("WPA")

    # Check for WEP
    if packet[Dot11Beacon].cap.privacy and not crypto_set:
        crypto_set.add("WEP")

    if not crypto_set:
        return "Open"
    return "/".join(sorted(list(crypto_set)))

def _process_wifi_packet(packet):
    """Scapy sniff callback to process live Wi-Fi packets."""
    try:
        # 1. Detect Access Points (APs) from Beacon frames
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            if bssid not in _wifi_aps:
                ssid_elt = packet.getlayer(Dot11Elt, ID=0)
                ssid = "<hidden>"
                if ssid_elt is not None:
                    try:
                        ssid = ssid_elt.info.decode()
                    except UnicodeDecodeError:
                        ssid = ssid_elt.info.hex()
                
                # Get RSSI if RadioTap header is present
                rssi = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else None

                _wifi_aps[bssid] = WiFiDevice(
                    type="AP",
                    bssid=bssid,
                    ssid=ssid,
                    rssi=rssi,
                    security=_get_wifi_security(packet)
                )

        # 2. Detect Clients from Probe Requests
        elif packet.haslayer(Dot11ProbeReq):
            bssid = packet[Dot11].addr2
            # Filter out broadcast/null probes
            if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                ssid_elt = packet.getlayer(Dot11Elt, ID=0)
                probed_ssid = ""
                if ssid_elt is not None and ssid_elt.info:
                    try:
                        probed_ssid = ssid_elt.info.decode()
                    except UnicodeDecodeError:
                        probed_ssid = ssid_elt.info.hex()
                
                rssi = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else None

                if bssid not in _wifi_clients:
                    _wifi_clients[bssid] = WiFiDevice(
                        type="Client",
                        bssid=bssid,
                        rssi=rssi,
                        probed_ssids=[probed_ssid] if probed_ssid else []
                    )
                else:
                    # Add newly probed SSID if not already listed
                    if probed_ssid and probed_ssid not in _wifi_clients[bssid].probed_ssids:
                        _wifi_clients[bssid].probed_ssids.append(probed_ssid)
                    # Update RSSI
                    if rssi:
                         _wifi_clients[bssid].rssi = rssi

    except Exception as e:
        logger.error(f"Error processing Wi-Fi packet: {e}")

def scan_wifi_devices_live(iface: str, scan_duration: int = 15) -> List[WiFiDevice]:
    """
    Scans for nearby Wi-Fi devices (APs and Clients) in real-time.
    Requires a wireless interface in monitor mode.
    """
    if sniff is None:
        console.print("[bold red]Scapy library not found. Live Wi-Fi scan aborted.[/bold red]")
        return []

    # Clear global dicts before scan
    global _wifi_aps, _wifi_clients
    _wifi_aps = {}
    _wifi_clients = {}

    console.print(
        f"[bold cyan]Starting live Wi-Fi scan on {iface} for {scan_duration} seconds...[/bold cyan]"
    )
    console.print("[bold yellow]Note: Interface must be in monitor mode![/bold yellow]")
    
    try:
        sniff(iface=iface, prn=_process_wifi_packet, timeout=scan_duration, store=0)
    except Exception as e:
        console.print(f"[bold red]An error occurred during sniffing (check permissions/interface): {e}[/bold red]")
        return []

    console.print(f"[bold green]Live Wi-Fi scan complete. Found {len(_wifi_aps)} APs and {len(_wifi_clients)} clients.[/bold green]")
    return list(_wifi_aps.values()) + list(_wifi_clients.values())


# --- Active SDR Scanning ---

def scan_rf_spectrum_active(
    freq_start_mhz: float,
    freq_end_mhz: float,
    threshold_dbm: float = -30.0,
    sample_rate_mhz: float = 2.4,
    gain: str = "auto",
) -> RFScanReport:
    """
    Actively scans a frequency range using an RTL-SDR device to find strong signals.
    """
    if RtlSdr is None or np is None:
        msg = "pyrtlsdr and/or numpy not found. Active SDR scan aborted."
        console.print(f"[bold red]{msg}[/bold red]")
        return RFScanReport(
            scan_range_mhz=f"{freq_start_mhz}-{freq_end_mhz}",
            sample_rate_mhz=sample_rate_mhz,
            threshold_dbm=threshold_dbm,
            signals_found=0,
            signals=[],
            error=msg
        )

    scan_range_str = f"{freq_start_mhz}-{freq_end_mhz}"
    console.print(f"[bold cyan]Starting active SDR scan: {scan_range_str} MHz...[/bold cyan]")
    signals: List[RFSignal] = []

    try:
        sdr = RtlSdr()
        sdr.sample_rate = sample_rate_mhz * 1e6
        sdr.center_freq = ((freq_start_mhz + freq_end_mhz) / 2) * 1e6
        sdr.gain = gain
        
        # Calculate NFFT for good resolution
        nfft = 1024
        
        console.print(f"  [bold]Center Freq:[/] {sdr.center_freq / 1e6} MHz")
        console.print(f"  [bold]Sample Rate:[/] {sdr.sample_rate / 1e6} MHz")
        console.print(f"  [bold]Gain:[/] {sdr.gain}")
        console.print(f"  [bold]Threshold:[/] {threshold_dbm} dBm")
        console.print("Reading samples...")

        # Read samples and compute Power Spectral Density (PSD)
        # We use 'power' instead of 'psd' for dBm, and window=np.blackman_harris
        # num_samples = nfft * 10 # Read a few blocks
        # samples = sdr.read_samples(num_samples)
        # Note: read_samples is complex. A simpler way is to use the built-in psd().
        # This will scan the range centered at center_freq
        
        # A more robust scan sweeps the *entire* range
        center_freqs = np.arange(
            freq_start_mhz * 1e6, 
            freq_end_mhz * 1e6, 
            sdr.sample_rate  # Step by one sample_rate width
        )
        if not center_freqs.any():
             center_freqs = [sdr.center_freq] # At least scan the center
        
        all_signals = {}
        
        for cf in center_freqs:
            sdr.center_freq = cf
            console.print(f"Scanning segment centered at {cf/1e6:.2f} MHz...")
            
            # Using sdr.psd() is simpler than manual FFT
            # This returns power in dBm and frequencies
            try:
                psd_values, freqs = sdr.psd(nfft, 'dbm', np.blackman_harris)
            except Exception as e:
                # Can fail if SDR is disconnected mid-scan
                console.print(f"[bold red]Error reading PSD at {cf/1e6:.2f} MHz: {e}[/bold red]")
                continue

            # Find signals above threshold
            indices = np.where(psd_values > threshold_dbm)[0]
            
            for i in indices:
                freq_hz = freqs[i]
                power = psd_values[i]
                freq_mhz = freq_hz / 1_000_000
                
                # Check if this signal is part of an already detected peak
                is_new_signal = True
                for existing_freq in all_signals:
                    if abs(existing_freq - freq_mhz) < 0.05: # 50 kHz tolerance
                        is_new_signal = False
                        if power > all_signals[existing_freq].power_dbm:
                            # Update to the stronger peak
                            all_signals[existing_freq].power_dbm = power
                        break
                
                if is_new_signal:
                    signal = RFSignal(
                        frequency_mhz=freq_mhz,
                        power_dbm=power,
                        details=f"Signal at {freq_mhz:.3f} MHz detected with {power:.2f} dBm"
                    )
                    all_signals[freq_mhz] = signal

    except Exception as e:
        sdr.close()
        msg = f"An error occurred during SDR scan: {e}"
        console.print(f"[bold red]{msg}[/bold red]")
        return RFScanReport(
            scan_range_mhz=scan_range_str,
            sample_rate_mhz=sample_rate_mhz,
            threshold_dbm=threshold_dbm,
            signals_found=0,
            signals=[],
            error=msg
        )
    finally:
        if 'sdr' in locals():
            sdr.close()

    signals = list(all_signals.values())
    console.print(f"[bold green]Active SDR scan complete. Found {len(signals)} distinct signals.[/bold green]")
    
    return RFScanReport(
        scan_range_mhz=scan_range_str,
        sample_rate_mhz=sample_rate_mhz,
        threshold_dbm=threshold_dbm,
        signals_found=len(signals),
        signals=signals
    )


# --- Typer CLI Application ---

rfint_app = typer.Typer(
    help="Active Radio Frequency Intelligence (RFINT) tools."
)

@rfint_app.callback()
def rfint_callback():
    """
    Active RFINT module for hardware-based signal collection.
    Requires specialized hardware (SDR, Wi-Fi/BLE adapters).
    """
    pass

@rfint_app.command("ble", help="Scan for nearby Bluetooth (BLE) devices.")
def cli_scan_ble(
    duration: int = typer.Option(
        10, "--duration", "-d", help="Duration of the scan in seconds."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Scans for nearby Bluetooth Low Energy (BLE) devices.
    """
    if BleakScanner is None:
        console.print("[bold red]Bleak library not installed. Cannot run BLE scan.[/bold red]")
        raise typer.Exit(code=1)

    try:
        results = asyncio.run(scan_ble_devices(scan_duration=duration))
    except Exception as e:
        console.print(f"[bold red]An error occurred during BLE scan: {e}[/bold red]")
        raise typer.Exit(code=1)

    results_dict = [r.model_dump() for r in results]
    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))
    
    if results_dict:
        save_scan_to_db(target="ble_proximity_scan", module="rfint_ble", data=results_dict)

@rfint_app.command("wifi-live", help="Run a live Wi-Fi scan for APs and clients.")
def cli_scan_wifi_live(
    iface: str = typer.Argument(
        ..., help="Wireless interface to use (must be in monitor mode)."
    ),
    duration: int = typer.Option(
        15, "--duration", "-d", help="Duration of the scan in seconds."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Scans for nearby Wi-Fi devices (APs and Clients) in real-time.
    """
    if sniff is None:
        console.print("[bold red]Scapy library not installed. Cannot run Wi-Fi scan.[/bold red]")
        raise typer.Exit(code=1)

    results = scan_wifi_devices_live(iface=iface, scan_duration=duration)
    results_dict = [r.model_dump() for r in results]

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))

    if results_dict:
        save_scan_to_db(target=iface, module="rfint_wifi_live", data=results_dict)

@rfint_app.command("sdr-scan", help="Actively scan a radio frequency range with an SDR.")
def cli_scan_sdr(
    freq_start: float = typer.Option(
        ..., "--from", help="Start frequency in MHz (e.g., 433.0)."
    ),
    freq_end: float = typer.Option(
        ..., "--to", help="End frequency in MHz (e.g., 434.0)."
    ),
    threshold: float = typer.Option(
        -30.0, "--threshold", "-t", help="Power threshold (in dBm) to report a signal."
    ),
    sample_rate: float = typer.Option(
        2.4, "--rate", "-r", help="Sample rate in MHz (e.g., 2.4)."
    ),
    gain: str = typer.Option(
        "auto", "--gain", "-g", help="SDR gain (e.g., 'auto' or 32.8)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Uses an RTL-SDR to actively scan a frequency range for signals
    exceeding a power threshold.
    
    Examples:
    - IoT Sniffing (ISM): --from 433.0 --to 434.0
    - IoT Sniffing (ISM): --from 914.0 --to 916.0
    - Rogue Signal (GSM): --from 890.0 --to 915.0
    """
    if RtlSdr is None:
        console.print("[bold red]pyrtlsdr library not installed. Cannot run SDR scan.[/bold red]")
        raise typer.Exit(code=1)

    results_model = scan_rf_spectrum_active(
        freq_start_mhz=freq_start,
        freq_end_mhz=freq_end,
        threshold_dbm=threshold,
        sample_rate_mhz=sample_rate,
        gain=gain
    )
    results_dict = results_model.model_dump(exclude_none=True)

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))
    
    if results_model.signals:
        target = f"{freq_start}-{freq_end}MHz"
        save_scan_to_db(target=target, module="rfint_sdr_scan", data=results_dict)

if __name__ == "__main__":
    rfint_app()