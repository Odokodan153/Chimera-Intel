import unittest
import asyncio
import json
import typer
from typer.testing import CliRunner

from chimera_intel.core.vehicle_osint import search_vehicle_vin, vehicle_osint_app
from chimera_intel.core.schemas import VehicleScanResult

# A known valid, public VIN for a 2011 Ford F-150
# This is used to perform a live API call, as requested.
VALID_TEST_VIN = "1FTFW1ET4BFD12345"

# A known invalid VIN
INVALID_TEST_VIN = "12345ABCDE"

runner = CliRunner()

# Wrap the sub-app in a parent Typer for correct test invocation
app = typer.Typer()
app.add_typer(vehicle_osint_app, name="vehicle")


class TestVehicleOsint(unittest.IsolatedAsyncioTestCase):
    """
    Test cases for the vehicle_osint module.
    
    NOTE: These tests perform REAL network requests to the NHTSA vPIC API
    and do not use mocks, per the user request. They require a live
    internet connection to pass.
    """

    async def test_search_vehicle_vin_success(self):
        """Tests a successful VIN lookup using a real, valid VIN."""
        # Arrange
        # No mocks. We call the real function.
        
        # Act
        result = await search_vehicle_vin(VALID_TEST_VIN)

        # Assert
        self.assertIsInstance(result, VehicleScanResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.info)
        self.assertEqual(result.query_vin, VALID_TEST_VIN)
        self.assertEqual(result.info.Make, "FORD")
        self.assertEqual(result.info.Model, "F-150")
        self.assertEqual(result.info.ModelYear, "2011")

    async def test_search_vehicle_vin_invalid(self):
        """Tests a failed VIN lookup using an invalid VIN."""
        # Arrange
        # No mocks.
        
        # Act
        result = await search_vehicle_vin(INVALID_TEST_VIN)

        # Assert
        self.assertIsInstance(result, VehicleScanResult)
        self.assertIsNotNone(result.error)
        self.assertIn("VIN is invalid", result.error)
        self.assertIsNotNone(result.info)
        self.assertEqual(result.info.ErrorCode, "6") # ErrorCode 6: VIN is invalid

    # --- CLI Command Tests (Real Calls) ---

    def test_cli_vehicle_search_success(self):
        """Tests a successful run of the 'vehicle search' command with a real VIN."""
        # Arrange
        # No mocks.
        
        # Act
        result = runner.invoke(app, ["vehicle", "search", VALID_TEST_VIN])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn('"query_vin": "1FTFW1ET4BFD12345"', result.stdout)
        self.assertIn('"Make": "FORD"', result.stdout)
        self.assertIn('"Model": "F-150"', result.stdout)

    def test_cli_vehicle_search_invalid_vin(self):
        """Tests the CLI command with an invalid VIN."""
        # Arrange
        # No mocks.
        
        # Act
        result = runner.invoke(app, ["vehicle", "search", INVALID_TEST_VIN])
        
        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn(f'"query_vin": "{INVALID_TEST_VIN}"', result.stdout)
        self.assertIn("VIN is invalid", result.stdout)

    def test_cli_vehicle_search_no_vin(self):
        """Tests CLI failure when no VIN is provided."""
        # Arrange
        # We cannot mock get_active_project, so this test relies on
        # the real function failing when no VIN is given.
        
        # Act
        result = runner.invoke(app, ["vehicle", "search"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No VIN provided", result.stderr)

    def test_cli_vehicle_search_short_vin(self):
        """Tests CLI failure when a short VIN is provided."""
        # Arrange
        # No mocks.
        
        # Act
        result = runner.invoke(app, ["vehicle", "search", "12345"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("A valid 17-character VIN is required", result.stderr)


if __name__ == "__main__":
    unittest.main()