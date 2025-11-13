import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import json

# --- Mock hardware modules before importing the app ---
# This is crucial as the app module will try to import them

mock_bleak = MagicMock()
mock_bleak.BleakScanner = MagicMock()

mock_scapy = MagicMock()
mock_scapy.sniff = MagicMock()
mock_scapy.Dot11 = MagicMock()
mock_scapy.Dot11Beacon = MagicMock()
mock_scapy.Dot11ProbeReq = MagicMock()
mock_scapy.Dot11Elt = MagicMock()

mock_rtlsdr = MagicMock()
mock_rtlsdr.RtlSdr = MagicMock()

mock_numpy = MagicMock()
mock_numpy.where = MagicMock()
mock_numpy.arange = MagicMock()

# --- Apply patches ---
module_patches = {
    "bleak": mock_bleak,
    "scapy.all": mock_scapy,
    "rtlsdr": mock_rtlsdr,
    "numpy": mock_numpy,
}

# Use pytest's monkeypatch fixture to apply system-wide patches
@pytest.fixture(autouse=True)
def patch_hw_modules(monkeypatch):
    for module_name, mock_obj in module_patches.items():
        monkeypatch.setitem(__import__("sys").modules, module_name, mock_obj)
    # Ensure modules are re-imported with mocks
    if "chimera_intel.core.rfint" in __import__("sys").modules:
        del __import__("sys").modules["chimera_intel.core.rfint"]


# --- Now we can import the module ---
from chimera_intel.core.rfint import (
    rfint_app, 
    scan_ble_devices, 
    scan_wifi_devices_live, 
    _process_wifi_packet,
    scan_rf_spectrum_active
)

runner = CliRunner()

# --- Mock Data ---

# Mock BLE device and advertisement data
mock_bleak_device = MagicMock()
mock_bleak_device.address = "00:11:22:33:44:55"
mock_bleak_ad_data = MagicMock()
mock_bleak_ad_data.local_name = "TestDevice"
mock_bleak_ad_data.rssi = -50
mock_bleak_ad_data.service_uuids = ["180A", "180F"]
mock_bleak_ad_data.manufacturer_data = {0x004C: b'\x02\x15'} # Apple

# Mock Scapy packets
def get_mock_wifi_packets():
    # Mock Beacon (AP)
    mock_ap_pkt = MagicMock()
    mock_ap_pkt.haslayer.side_effect = lambda layer: layer == mock_scapy.Dot11Beacon
    mock_ap_pkt.dBm_AntSignal = -60
    mock_ap_pkt.__getitem__.side_effect = lambda layer: (
        MagicMock(addr2="AA:AA:AA:AA:AA:AA") if layer == mock_scapy.Dot11 else None
    )
    mock_ssid_elt = MagicMock(info=b"Test_AP")
    mock_ap_pkt.getlayer.side_effect = lambda layer, ID: (
        mock_ssid_elt if ID == 0 else MagicMock() # RSN
    )
    
    # Mock Probe Request (Client)
    mock_client_pkt = MagicMock()
    mock_client_pkt.haslayer.side_effect = lambda layer: layer == mock_scapy.Dot11ProbeReq
    mock_client_pkt.dBm_AntSignal = -75
    mock_client_pkt.__getitem__.side_effect = lambda layer: (
        MagicMock(addr2="BB:BB:BB:BB:BB:BB") if layer == mock_scapy.Dot11 else None
    )
    mock_probe_ssid_elt = MagicMock(info=b"MyHomeWiFi")
    mock_client_pkt.getlayer.side_effect = lambda layer, ID: (
        mock_probe_ssid_elt if ID == 0 else None
    )
    
    return [mock_ap_pkt, mock_client_pkt]

# --- Tests ---

@pytest.mark.asyncio
@patch("chimera_intel.core.rfint.BleakScanner", new_callable=MagicMock)
async def test_scan_ble_devices(MockBleakScanner):
    """Tests the BLE scanning logic."""
    # Configure the mock scanner
    mock_scanner_instance = MockBleakScanner.return_value
    mock_scanner_instance.start = AsyncMock()
    mock_scanner_instance.stop = AsyncMock()
    
    # This simulates the callback being called by the scanner
    def register_side_effect(callback):
        callback(mock_bleak_device, mock_bleak_ad_data)
    mock_scanner_instance.register_detection_callback.side_effect = register_side_effect

    results = await scan_ble_devices(scan_duration=0.1)
    
    assert len(results) == 1
    assert results[0].address == "00:11:22:33:44:55"
    assert results[0].name == "TestDevice"
    assert results[0].rssi == -50
    assert "180A" in results[0].services
    assert results[0].manufacturer_data["0x4c"] == "0215"
    mock_scanner_instance.start.assert_called_once()
    mock_scanner_instance.stop.assert_called_once()


@patch("chimera_intel.core.rfint.sniff", new_callable=MagicMock)
def test_scan_wifi_devices_live(mock_sniff):
    """Tests the live Wi-Fi scanning logic."""
    mock_packets = get_mock_wifi_packets()
    
    # Simulate sniff calling the callback
    def sniff_side_effect(iface, prn, timeout, store):
        for pkt in mock_packets:
            prn(pkt)
    mock_sniff.side_effect = sniff_side_effect

    results = scan_wifi_devices_live(iface="mon0", scan_duration=0.1)
    
    mock_sniff.assert_called_with(iface="mon0", prn=_process_wifi_packet, timeout=0.1, store=0)
    assert len(results) == 2
    
    ap = next(r for r in results if r.type == "AP")
    client = next(r for r in results if r.type == "Client")

    assert ap.bssid == "AA:AA:AA:AA:AA:AA"
    assert ap.ssid == "Test_AP"
    assert ap.rssi == -60
    assert "WPA2/3" in ap.security # From mock getlayer
    
    assert client.bssid == "BB:BB:BB:BB:BB:BB"
    assert client.rssi == -75
    assert "MyHomeWiFi" in client.probed_ssids


@patch("chimera_intel.core.rfint.RtlSdr", new_callable=MagicMock)
def test_scan_rf_spectrum_active(MockRtlSdr):
    """Tests the active SDR scanning logic."""
    # Configure mock SDR instance
    mock_sdr_instance = MockRtlSdr.return_value
    mock_sdr_instance.close = MagicMock()
    
    # Mock PSD results
    mock_freqs = mock_numpy.array([433.0e6, 433.1e6, 433.2e6, 433.3e6])
    mock_psd_values = mock_numpy.array([-50.0, -25.0, -40.0, -15.0]) # Two peaks
    mock_sdr_instance.psd.return_value = (mock_psd_values, mock_freqs)
    
    # Mock numpy 'where'
    mock_numpy.where.return_value = (mock_numpy.array([1, 3]),) # Indices of peaks
    mock_numpy.arange.return_value = mock_numpy.array([433.0e6]) # Simulate one sweep

    results = scan_rf_spectrum_active(
        freq_start_mhz=433.0,
        freq_end_mhz=434.0,
        threshold_dbm=-30.0
    )
    
    assert results.error is None
    assert results.signals_found == 2
    assert results.signals[0].frequency_mhz == 433.1
    assert results.signals[0].power_dbm == -25.0
    assert results.signals[1].frequency_mhz == 433.3
    assert results.signals[1].power_dbm == -15.0
    mock_sdr_instance.close.assert_called_once()


# --- CLI Tests ---

@patch("chimera_intel.core.rfint.scan_ble_devices", new_callable=AsyncMock)
@patch("chimera_intel.core.rfint.save_scan_to_db", MagicMock())
def test_cli_scan_ble(mock_scan):
    """Tests the 'ble' CLI command."""
    mock_scan.return_value = [
        MagicMock(model_dump=MagicMock(return_value={"address": "00:11..", "rssi": -50}))
    ]
    
    result = runner.invoke(rfint_app, ["ble", "-d", "1"])
    
    assert result.exit_code == 0
    assert '"address": "00:11.."' in result.stdout
    mock_scan.assert_called_with(scan_duration=1)

@patch("chimera_intel.core.rfint.scan_wifi_devices_live", MagicMock())
@patch("chimera_intel.core.rfint.save_scan_to_db", MagicMock())
def test_cli_scan_wifi_live(mock_scan):
    """Tests the 'wifi-live' CLI command."""
    mock_scan.return_value = [
        MagicMock(model_dump=MagicMock(return_value={"bssid": "AA:AA..", "type": "AP"}))
    ]
    
    result = runner.invoke(rfint_app, ["wifi-live", "mon0", "-d", "5"])
    
    assert result.exit_code == 0
    assert '"bssid": "AA:AA.."' in result.stdout
    mock_scan.assert_called_with(iface="mon0", scan_duration=5)

@patch("chimera_intel.core.rfint.scan_rf_spectrum_active", MagicMock())
@patch("chimera_intel.core.rfint.save_scan_to_db", MagicMock())
def test_cli_scan_sdr(mock_scan):
    """Tests the 'sdr-scan' CLI command."""
    mock_scan.return_value = MagicMock(
        signals=[MagicMock(frequency_mhz=433.9)],
        model_dump=MagicMock(return_value={
            "scan_range_mhz": "433.0-434.0",
            "signals_found": 1,
            "signals": [{"frequency_mhz": 433.9, "power_dbm": -20.0}]
        })
    )
    
    result = runner.invoke(
        rfint_app,
        ["sdr-scan", "--from", "433.0", "--to", "434.0", "-t", "-25.0"]
    )
    
    assert result.exit_code == 0
    assert '"frequency_mhz": 433.9' in result.stdout
    mock_scan.assert_called_with(
        freq_start_mhz=433.0,
        freq_end_mhz=434.0,
        threshold_dbm=-25.0,
        sample_rate_mhz=2.4, # default
        gain='auto' # default
    )