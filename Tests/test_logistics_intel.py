import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from chimera_intel.core.logistics_intel import (
    track_shipment,
    ShipmentDetails,
    TrackingUpdate,
    # --- Import new items ---
    get_vessel_track_by_imo,
    analyze_supply_chain_anomalies,
    VesselTrackResult,
    VesselInfo,
    PortVisit,
    TradeManifestResult,
    TradeManifest,
    SupplyChainAnalysisResult
)
# Import schemas needed for mocking MLINT integration
from chimera_intel.core.schemas import JurisdictionRisk, TradeCorrelationResult, PaymentData, TradeData, SupplyChainAnomaly
from chimera_intel.core.logistics_intel import app as cli_app
# Import the module itself to mock its dependencies
import chimera_intel.core.logistics_intel as logistics_intel_module
import httpx
from typer.testing import CliRunner
from datetime import date


class TestLogisticsIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for the logistics_intel module."""

    # --- Existing Tests ---

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_success(self, mock_post, mock_api_keys):
        """Tests a successful shipment tracking call."""
        mock_api_keys.easypost_api_key = "fake_key"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "tracking_code": "EZ123456789",
            "carrier": "USPS",
            "status": "in_transit",
            "est_delivery_date": "2025-01-05T12:00:00Z",
            "tracking_details": [
                {
                    "status": "in_transit",
                    "message": "On its way",
                    "datetime": "2025-01-01T12:00:00Z",
                }
            ],
        }
        mock_post.return_value = mock_response
        mock_response.raise_for_status = (
            MagicMock()
        )  # Ensure raise_for_status does nothing

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsInstance(result, ShipmentDetails)
        self.assertEqual(result.status, "in_transit")
        self.assertEqual(result.estimated_delivery_date, "2025-01-05T12:00:00Z")
        self.assertEqual(len(result.updates), 1)
        self.assertEqual(result.updates[0].message, "On its way")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    async def test_track_shipment_no_api_key(self, mock_api_keys):
        """Tests the function when the API key is not set."""
        mock_api_keys.easypost_api_key = None
        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertIn("API key is not configured", result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_api_http_error(self, mock_post, mock_api_keys):
        """Tests the function when the API returns an HTTP error."""
        mock_api_keys.easypost_api_key = "fake_key"

        # Mock the response within the exception
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.text = '{"error": "Invalid API key"}'

        mock_post.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=MagicMock(),
            response=mock_response,
        )

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertIn("API error", result.error)
        self.assertIn("Invalid API key", result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_general_exception(self, mock_post, mock_api_keys):
        """Tests the function during a general exception."""
        mock_api_keys.easypost_api_key = "fake_key"
        mock_post.side_effect = Exception("A general error")

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error, "A general error")


    # --- New PHYSINT Tests ---

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch("chimera_intel.core.logistics_intel.httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_get_vessel_track_success(self, mock_get, mock_api_keys):
        """Tests a successful vessel track call."""
        mock_api_keys.marinetraffic_api_key = "fake_key"
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        # This is the mock API response we expect from the provider
        mock_response.json.return_value = {
            "vessel_info": {
                "imo": "9876543", 
                "mmsi": "311000123", 
                "name": "MV Chimera", 
                "current_lat": 34.05, 
                "current_lon": -118.25
            },
            "port_calls": [
                {"port_name": "Shanghai", "country_code": "CHN", "arrival_timestamp": "2024-10-01T12:00:00Z", "departure_timestamp": "2024-10-03T18:00:00Z"},
                {"port_name": "Long Beach", "country_code": "USA", "arrival_timestamp": "2024-10-25T06:00:00Z", "departure_timestamp": "2024-10-27T14:00:00Z"}
            ]
        }
        mock_get.return_value = mock_response
        mock_response.raise_for_status = MagicMock()

        # This calls the REAL function, which is now being tricked by the mocked httpx client
        result = await get_vessel_track_by_imo("9876543")

        self.assertIsInstance(result, VesselTrackResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.vessel_info.name, "MV Chimera")
        self.assertEqual(result.total_port_calls, 2)
        self.assertEqual(result.port_calls[0].port_name, "Shanghai")
        self.assertEqual(result.port_calls[0].country, "CHN")

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    async def test_get_vessel_track_no_api_key(self, mock_api_keys):
        """Tests vessel tracking with no API key."""
        mock_api_keys.marinetraffic_api_key = None
        result = await get_vessel_track_by_imo("9876543")
        self.assertIsNotNone(result.error)
        self.assertIn("MARINETRAFFIC_API_KEY not configured", result.error)


    @patch("chimera_intel.core.logistics_intel.get_jurisdiction_risk")
    def test_analyze_supply_chain_anomalies(self, mock_get_jurisdiction_risk):
        """Tests the anomaly detection logic."""
        # This is a critical mock for the MLINT integration
        logistics_intel_module.get_jurisdiction_risk = mock_get_jurisdiction_risk

        # Setup: Mock that Panama is a high-risk port
        mock_get_jurisdiction_risk.side_effect = lambda country: {
            "PAN": JurisdictionRisk(country="PAN", risk_level="Medium", risk_score=60, details="..."),
            "CHN": JurisdictionRisk(country="CHN", risk_level="Low", risk_score=10, details="..."),
            "USA": JurisdictionRisk(country="USA", risk_level="Low", risk_score=10, details="..."),
        }.get(country.upper(), JurisdictionRisk(country=country, risk_level="Low", risk_score=10, details="..."))

        # 1. Manifest from Shanghai (CHN) to Long Beach (USA)
        manifest = TradeManifest(
            bill_of_lading_id="BL-12345",
            shipper_name="Shanghai Widgets Inc.",
            consignee_name="MegaCorp Logistics",
            vessel_imo="9876543",
            port_of_lading="Shanghai, CHN",
            port_of_discharge="Long Beach, USA",
            cargo_description="Electronics",
            ship_date="2024-10-03"
        )
        
        # 2. Vessel track for IMO 9876543
        vessel_track = VesselTrackResult(
            vessel_info=VesselInfo(imo="9876543", name="MV Chimera"),
            port_calls=[
                PortVisit(port_name="Shanghai", country="CHN", arrival_timestamp="...", departure_timestamp="..."),
                # This is the anomalous stop
                PortVisit(port_name="Panama Canal", country="PAN", arrival_timestamp="...", departure_timestamp="..."),
                PortVisit(port_name="Long Beach", country="USA", arrival_timestamp="...", departure_timestamp="...")
            ],
            total_port_calls=3
        )

        # Run analysis
        result = analyze_supply_chain_anomalies([manifest], {"9876543": vessel_track})
        
        self.assertIsInstance(result, SupplyChainAnalysisResult)
        self.assertEqual(result.total_anomalies, 2)
        
        anomaly_types = {a.anomaly_type for a in result.anomalies_found}
        self.assertIn("High-Risk Port", anomaly_types)
        self.assertIn("Suspicious Routing", anomaly_types)
        
        # Check that the "Suspicious Routing" anomaly is correct
        suspicious_routing_anomaly = next(a for a in result.anomalies_found if a.anomaly_type == "Suspicious Routing")
        self.assertIn("Panama Canal", suspicious_routing_anomaly.description)


    # --- CLI Tests ---

    def setUp(self):
        self.runner = CliRunner()

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_success(self, mock_asyncio_run):
        """Tests the CLI 'track' command for a successful lookup."""
        mock_updates = [
            TrackingUpdate(
                status="pre_transit",
                message="Label created",
                timestamp="2025-01-01T10:00:00Z",
            )
        ]
        mock_result = ShipmentDetails(
            tracking_code="EZ123",
            carrier="USPS",
            status="pre_transit",
            estimated_delivery_date="2025-01-05",
            updates=mock_updates,
            error=None,
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["track", "EZ123", "--carrier", "USPS"], env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Status for EZ123 (USPS): pre_transit", result.stdout)
        self.assertIn("Estimated Delivery: 2025-01-05", result.stdout)
        self.assertIn("Tracking History", result.stdout)
        self.assertIn("Label created", result.stdout)

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_error(self, mock_asyncio_run):
        """Tests the CLI 'track' command when an error occurs."""
        mock_result = ShipmentDetails(
            tracking_code="EZ123",
            carrier="USPS",
            status="Error",
            updates=[],
            error="No API key",
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["track", "EZ123", "--carrier", "USPS"], env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 1)  # CLI should exit with 1 on error
        self.assertIn("Error:", result.stderr)
        self.assertIn("No API key", result.stderr)
        self.assertNotIn(
            "Tracking History", result.stdout
        )  # Table should not be printed

    def test_cli_track_missing_carrier(self):
        """Tests the CLI when the required --carrier option is missing."""
        result = self.runner.invoke(cli_app, ["track", "EZ123"], env={"NO_COLOR": "1"})

        self.assertNotEqual(result.exit_code, 0)  # Fails due to missing option
        self.assertIn("Missing option", result.stderr)
        self.assertIn("--carrier", result.stderr)


    # --- New PHYSINT CLI Tests ---
    
    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_vessel_success(self, mock_asyncio_run):
        """Tests the 'track-vessel' CLI command for a successful lookup."""
        mock_result = VesselTrackResult(
            vessel_info=VesselInfo(
                imo="9876543", name="MV Chimera", current_lat=34.05, current_lon=-118.25
            ),
            port_calls=[
                PortVisit(port_name="Shanghai", country="CHN", arrival_timestamp="2024-10-01T12:00:00Z", departure_timestamp="2024-10-03T18:00:00Z")
            ],
            total_port_calls=1
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["track-vessel", "9876543"], env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Vessel: MV Chimera (IMO: 9876543)", result.stdout)
        self.assertIn("Current Location:", result.stdout)
        self.assertIn("Historical Port Calls", result.stdout)
        self.assertIn("Shanghai", result.stdout)

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_vessel_error(self, mock_asyncio_run):
        """Tests the 'track-vessel' CLI command when an error occurs."""
        mock_result = VesselTrackResult(error="No API key")
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["track-vessel", "9876543"], env={"NO_COLOR": "1"}
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error: No API key", result.stderr)

    @patch("chimera_intel.core.logistics_intel.resolve_target", return_value="MegaCorp")
    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_find_manifests_success(self, mock_asyncio_run, mock_resolve):
        """Tests the 'find-manifests' CLI command for a successful lookup."""
        mock_result = TradeManifestResult(
            company_name="MegaCorp",
            manifests=[
                TradeManifest(
                    bill_of_lading_id="BL-123",
                    ship_date="2024-10-03",
                    shipper_name="Shipper Inc.",
                    consignee_name="MegaCorp",
                    vessel_imo="9876543",
                    port_of_lading="Shanghai, CHN",
                    port_of_discharge="Long Beach, USA",
                    cargo_description="Widgets"
                )
            ],
            total_manifests=1
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["find-manifests", "MegaCorp"], env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 manifests for MegaCorp", result.stdout)
        self.assertIn("Shipping Manifests", result.stdout)
        self.assertIn("BL-123", result.stdout)
        self.assertIn("Widgets", result.stdout)

    @patch("chimera_intel.core.logistics_intel.resolve_target", return_value="MegaCorp")
    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_analyze_supply_chain_success(self, mock_asyncio_run, mock_resolve):
        """Tests the 'analyze-supply-chain' CLI command for a successful analysis."""
        # This mocks the entire 'analyze' async function
        mock_result = SupplyChainAnalysisResult(
            target_company="MegaCorp",
            analysis_summary="Analysis complete. Found 1 anomalies across 1 manifests.",
            anomalies_found=[
                SupplyChainAnomaly(
                    anomaly_type="Suspicious Routing",
                    description="Vessel made unscheduled stop in Panama, PAN",
                    severity="High",
                    related_bill_of_lading="BL-123"
                )
            ],
            total_anomalies=1
        )
        
        # Mock the MLINT dependency
        mock_risk_func = MagicMock()
        logistics_intel_module.get_jurisdiction_risk = mock_risk_func
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, ["analyze-supply-chain", "MegaCorp"], env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Supply Chain Analysis for MegaCorp", result.stdout)
        self.assertIn("Detected Anomalies", result.stdout)
        self.assertIn("Suspicious Routing", result.stdout)
        self.assertIn("Panama, PAN", result.stdout)

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_correlate_payment_success(self, mock_asyncio_run):
        """Tests the 'correlate-payment' MLINT integration command."""
        
        # Mock the MLINT dependency
        mock_correlate_func = MagicMock()
        logistics_intel_module.correlate_trade_payment = mock_correlate_func

        mock_result = TradeCorrelationResult(
            payment=PaymentData(
                payment_id="P123", sender_name="Shipper", receiver_name="Importer",
                amount=10000, currency="USD", date=date(2024, 10, 1)
            ),
            trade_document=TradeData(
                trade_document_id="T456", exporter_name="Shipper", importer_name="Importer",
                invoice_amount=10000, currency="USD", date=date(2024, 10, 1),
                description_of_goods="Widgets"
            ),
            is_correlated=True,
            confidence="High",
            correlation_score=1.0,
            mismatches=[]
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(
            cli_app, 
            ["correlate-payment", "--payment-id", "P123", "--trade-doc-id", "T456"], 
            env={"NO_COLOR": "1"}
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Trade Correlation Report", result.stdout)
        self.assertIn("Result: Correlated", result.stdout)
        self.assertIn("Confidence: High", result.stdout)
        self.assertNotIn("Mismatches Found", result.stdout)


if __name__ == "__main__":
    unittest.main()