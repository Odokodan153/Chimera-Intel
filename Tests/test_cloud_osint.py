import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner

from chimera_intel.core.cloud_osint import (
    check_s3_bucket,
    find_cloud_assets,
    check_azure_blob,
    check_gcs_bucket,
    cloud_osint_app,
)
from chimera_intel.core.schemas import (
    S3Bucket,
    AzureBlobContainer,
    GCSBucket,
    ProjectConfig,
    CloudOSINTResult,
)

runner = CliRunner()


class TestCloudOsint(unittest.TestCase):
    """Test cases for the cloud_osint module."""

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_s3_bucket_public(self, mock_async_client):
        """Tests checking a bucket that exists and is public."""
        # Arrange

        mock_head_response = MagicMock(spec=Response, status_code=200)
        mock_get_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.head.return_value = mock_head_response
        mock_async_client.get.return_value = mock_get_response

        # Act

        result = asyncio.run(check_s3_bucket("public-bucket"))

        # Assert

        self.assertIsNotNone(result)
        self.assertIsInstance(result, S3Bucket)
        self.assertEqual(result.name, "public-bucket")
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_s3_bucket_private(self, mock_async_client):
        """Tests checking a bucket that exists but is private (returns 403)."""
        # Arrange: HEAD is successful (bucket exists), but GET fails (it's private)

        mock_head_response = MagicMock(spec=Response, status_code=200)
        mock_get_response = MagicMock(spec=Response, status_code=403)
        mock_async_client.head.return_value = mock_head_response
        mock_async_client.get.return_value = mock_get_response

        # Act

        result = asyncio.run(check_s3_bucket("private-bucket"))

        # Assert

        self.assertIsNotNone(result)
        self.assertIsInstance(result, S3Bucket)
        self.assertFalse(result.is_public)
        self.assertEqual(result.name, "private-bucket")

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_azure_blob_public(self, mock_async_client):
        """Tests checking a public Azure blob container."""
        # Arrange

        mock_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.get.return_value = mock_response

        # Act

        result = asyncio.run(check_azure_blob("public-container"))

        # Assert

        self.assertIsNotNone(result)
        self.assertIsInstance(result, AzureBlobContainer)
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_azure_blob_network_error(self, mock_async_client):
        """Tests the Azure blob check when a network error occurs."""
        # Arrange

        mock_async_client.get.side_effect = RequestError("Connection timeout")

        # Act

        result = asyncio.run(check_azure_blob("some-container"))

        # Assert

        self.assertIsNone(result)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_gcs_bucket_public(self, mock_async_client):
        """Tests checking a public GCS bucket."""
        # Arrange

        mock_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.get.return_value = mock_response

        # Act

        result = asyncio.run(check_gcs_bucket("public-gcs-bucket"))

        # Assert

        self.assertIsNotNone(result)
        self.assertIsInstance(result, GCSBucket)
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.check_s3_bucket", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_azure_blob", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_gcs_bucket", new_callable=AsyncMock)
    def test_find_cloud_assets_main_logic(
        self, mock_check_gcs, mock_check_azure, mock_check_s3
    ):
        """
        Tests the main asset finding logic across all cloud providers.
        """
        # Arrange

        mock_check_s3.side_effect = lambda name: (
            S3Bucket(name=name, url="", is_public=True)
            if name == "mycompany-assets"
            else None
        )
        mock_check_azure.side_effect = lambda name: (
            AzureBlobContainer(name=name, url="", is_public=True)
            if name == "mycompany-data"
            else None
        )
        mock_check_gcs.side_effect = lambda name: (
            GCSBucket(name=name, url="", is_public=True)
            if name == "mycompany-backup"
            else None
        )

        # Act

        result = asyncio.run(find_cloud_assets("mycompany"))

        # Assert

        self.assertEqual(len(result.found_s3_buckets), 1)
        self.assertEqual(len(result.found_azure_containers), 1)
        self.assertEqual(len(result.found_gcs_buckets), 1)
        self.assertEqual(result.found_s3_buckets[0].name, "mycompany-assets")
        self.assertEqual(result.found_azure_containers[0].name, "mycompany-data")
        self.assertEqual(result.found_gcs_buckets[0].name, "mycompany-backup")

    @patch("chimera_intel.core.cloud_osint.check_s3_bucket", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_azure_blob", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_gcs_bucket", new_callable=AsyncMock)
    def test_find_cloud_assets_no_results(
        self, mock_check_gcs, mock_check_azure, mock_check_s3
    ):
        """
        Tests the asset finding logic when no cloud assets are found.
        """
        # Arrange: Simulate that all checks return None

        mock_check_s3.return_value = None
        mock_check_azure.return_value = None
        mock_check_gcs.return_value = None

        # Act

        result = asyncio.run(find_cloud_assets("nonexistentcompany"))

        # Assert

        self.assertEqual(len(result.found_s3_buckets), 0)
        self.assertEqual(len(result.found_azure_containers), 0)
        self.assertEqual(len(result.found_gcs_buckets), 0)

    # --- Project-Aware CLI Tests ---

    @patch("chimera_intel.core.cloud_osint.get_active_project")
    @patch("chimera_intel.core.cloud_osint.find_cloud_assets", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.save_scan_to_db")
    # Add patch for save_or_print_results
    @patch("chimera_intel.core.cloud_osint.save_or_print_results")
    def test_cli_cloud_run_with_project(
        self, mock_save_print, mock_save_db, mock_find_assets, mock_get_project
    ):
        """Tests the CLI command using an active project's company name."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="CloudTest",
            created_at="2025-01-01",
            company_name="Project Cloud Inc",
        )
        mock_get_project.return_value = mock_project
        mock_find_assets.return_value = CloudOSINTResult(
            target_keyword="projectcloudinc"
        )

        # Act

        result = runner.invoke(cloud_osint_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        # Check stderr for Rich Console output
        self.assertIn(
            "Using keyword 'projectcloudinc' from active project", result.stderr
        )
        mock_find_assets.assert_awaited_with("projectcloudinc")
        mock_save_db.assert_called_once()
        mock_save_print.assert_called_once() # Verify this is also called

    @patch("chimera_intel.core.cloud_osint.get_active_project")
    # Add patches for all side-effects, even if they aren't expected to run
    @patch("chimera_intel.core.cloud_osint.find_cloud_assets", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.save_scan_to_db")
    @patch("chimera_intel.core.cloud_osint.save_or_print_results")
    def test_cli_cloud_run_no_keyword_no_project(
        self, mock_save_print, mock_save_db, mock_find_assets, mock_get_project
    ):
        """Tests CLI failure when no keyword is given and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        result = runner.invoke(cloud_osint_app, ["run"])

        # Assert

        # The exit code should now be 1 as expected
        self.assertEqual(result.exit_code, 1)
        # Check stderr for the Rich Console error message
        self.assertIn("No keyword provided and no active project", result.stderr)
        # Ensure the other functions were not called
        mock_find_assets.assert_not_called()
        mock_save_db.assert_not_called()
        mock_save_print.assert_not_called()


if __name__ == "__main__":
    unittest.main()