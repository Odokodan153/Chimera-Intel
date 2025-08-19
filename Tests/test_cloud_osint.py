import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import Response
from chimera_intel.core.cloud_osint import check_s3_bucket, find_s3_buckets
from chimera_intel.core.schemas import S3Bucket


class TestCloudOsint(unittest.TestCase):
    """Test cases for the cloud_osint module."""

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_s3_bucket_public(self, mock_async_client):
        """Tests checking a bucket that exists and is public."""
        # HEAD request gets a 200, GET request also gets a 200

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
    def test_check_s3_bucket_private(self, mock_async_client):
        """Tests checking a bucket that exists but is private (Forbidden)."""
        # HEAD request gets a 200, but GET request gets a 403 Forbidden

        mock_head_response = MagicMock(spec=Response, status_code=200)
        mock_get_response = MagicMock(spec=Response, status_code=403)
        mock_async_client.head.return_value = mock_head_response
        mock_async_client.get.return_value = mock_get_response

        result = asyncio.run(check_s3_bucket("private-bucket"))

        self.assertIsNotNone(result)
        self.assertEqual(result.name, "private-bucket")
        self.assertFalse(result.is_public)

    @patch("chimera_intel.core.cloud_osint.async_client", new_callable=AsyncMock)
    def test_check_s3_bucket_not_found(self, mock_async_client):
        """Tests checking a bucket that does not exist."""
        # HEAD request gets a 404 Not Found

        mock_head_response = MagicMock(spec=Response, status_code=404)
        mock_async_client.head.return_value = mock_head_response

        result = asyncio.run(check_s3_bucket("non-existent-bucket"))

        self.assertIsNone(result)
        # Ensure the GET request was not even made

        mock_async_client.get.assert_not_called()

    @patch("chimera_intel.core.cloud_osint.check_s3_bucket", new_callable=AsyncMock)
    def test_find_s3_buckets_logic(self, mock_check_bucket):
        """
        Tests the main bucket finding logic.

        Args:
            mock_check_bucket (AsyncMock): A mock for the `check_s3_bucket` function.
        """
        # Simulate that only one of the permutations returns a result

        mock_check_bucket.side_effect = lambda name: (
            S3Bucket(name=name, url=f"http://{name}.s3...", is_public=True)
            if name == "mycompany-assets"
            else None
        )

        result = asyncio.run(find_s3_buckets("mycompany"))

        self.assertEqual(len(result.found_buckets), 1)
        self.assertEqual(result.found_buckets[0].name, "mycompany-assets")
        # Check that the mock was called for all permutations

        self.assertGreater(mock_check_bucket.call_count, 5)


if __name__ == "__main__":
    unittest.main()
