import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import Response
from chimera_intel.core.cloud_osint import (
    check_s3_bucket,
    find_cloud_assets,
    check_azure_blob,
    check_gcs_bucket,
)
from chimera_intel.core.schemas import S3Bucket, AzureBlobContainer, GCSBucket


class TestCloudOsint(unittest.TestCase):
    """Test cases for the cloud_osint module."""

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_s3_bucket_public(self, mock_async_client):
        """Tests checking a bucket that exists and is public."""
        mock_head_response = MagicMock(spec=Response, status_code=200)
        mock_get_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.head.return_value = mock_head_response
        mock_async_client.get.return_value = mock_get_response

        result = asyncio.run(check_s3_bucket("public-bucket"))

        self.assertIsNotNone(result)
        self.assertIsInstance(result, S3Bucket)
        self.assertEqual(result.name, "public-bucket")
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_azure_blob_public(self, mock_async_client):
        """Tests checking a public Azure blob container."""
        mock_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.get.return_value = mock_response

        result = asyncio.run(check_azure_blob("public-container"))

        self.assertIsNotNone(result)
        self.assertIsInstance(result, AzureBlobContainer)
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_gcs_bucket_public(self, mock_async_client):
        """Tests checking a public GCS bucket."""
        mock_response = MagicMock(spec=Response, status_code=200)
        mock_async_client.get.return_value = mock_response

        result = asyncio.run(check_gcs_bucket("public-gcs-bucket"))

        self.assertIsNotNone(result)
        self.assertIsInstance(result, GCSBucket)
        self.assertTrue(result.is_public)

    @patch("chimera_intel.core.cloud_osint.check_s3_bucket", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_azure_blob", new_callable=AsyncMock)
    @patch("chimera_intel.core.cloud_osint.check_gcs_bucket", new_callable=AsyncMock)
    def test_find_cloud_assets_logic(
        self, mock_check_gcs, mock_check_azure, mock_check_s3
    ):
        """
        Tests the main asset finding logic across all cloud providers.
        """
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

        result = asyncio.run(find_cloud_assets("mycompany"))

        self.assertEqual(len(result.found_s3_buckets), 1)
        self.assertEqual(len(result.found_azure_containers), 1)
        self.assertEqual(len(result.found_gcs_buckets), 1)
        self.assertEqual(result.found_s3_buckets[0].name, "mycompany-assets")
        self.assertEqual(result.found_azure_containers[0].name, "mycompany-data")
        self.assertEqual(result.found_gcs_buckets[0].name, "mycompany-backup")


if __name__ == "__main__":
    unittest.main()
