import unittest
import os
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
from celery.result import EagerResult

from chimera_intel.core.data_pipeline import pipeline_app, ingest_url_task

# Set dummy env vars for testing
os.environ["S3_BUCKET"] = "test-bucket"
os.environ["POSTGRES_DSN"] = "postgresql://test:test@localhost/test"
os.environ["ELASTICSEARCH_URL"] = "http://localhost:9200"
os.environ["CELERY_BROKER_URL"] = "memory://"
os.environ["CELERY_RESULT_BACKEND"] = "cache+memory://"

# Configure Celery for eager (synchronous) testing
ingest_url_task.app.conf.update(CELERY_TASK_ALWAYS_EAGER=True)

class TestDataPipeline(unittest.TestCase):
    """Test cases for the data ingestion pipeline."""

    def setUp(self):
        self.runner = CliRunner()
        self.test_url = "http://example.com"
        self.mock_html_content = "<html><head><title>Example</title></head><body>Test Content</body></html>"
        self.mock_page_text = "Example Test Content"
        self.mock_hash = "f38b1167e456619a9d36364c767f3f338719d8f6f578c772e8f1790403767f81"


    @patch("chimera_intel.core.data_pipeline.index_in_elasticsearch")
    @patch("chimera_intel.core.data_pipeline.log_to_postgres")
    @patch("chimera_intel.core.data_pipeline.upload_to_s3")
    @patch("chimera_intel.core.data_pipeline.scrape_static_page")
    @patch("chimera_intel.core.data_pipeline.asyncio.run")
    def test_cli_ingest_static(
        self,
        mock_asyncio_run,
        mock_scrape_static,
        mock_upload_s3,
        mock_log_pg,
        mock_index_es,
    ):
        """Tests the 'pipeline ingest' CLI command for a static page."""
        # Arrange
        mock_scrape_static.return_value = (self.mock_html_content, "Example")
        mock_upload_s3.return_value = f"raw_pages/{self.mock_hash}.html"
        mock_log_pg.return_value = 1
        mock_index_es.return_value = self.mock_hash
        
        # Act
        result = self.runner.invoke(
            pipeline_app, ["ingest", self.test_url]
        )
        
        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Ingestion Complete", result.stdout)
        self.assertIn(f'"url": "{self.test_url}"', result.stdout)
        self.assertIn('"status": "SUCCESS"', result.stdout)
        self.assertIn(f'"content_hash": "{self.mock_hash}"', result.stdout)
        
        mock_scrape_static.assert_called_with(self.test_url)
        mock_asyncio_run.assert_not_called()
        mock_upload_s3.assert_called_once()
        mock_log_pg.assert_called_once()
        mock_index_es.assert_called_once()


    @patch("chimera_intel.core.data_pipeline.index_in_elasticsearch")
    @patch("chimera_intel.core.data_pipeline.log_to_postgres")
    @patch("chimera_intel.core.data_pipeline.upload_to_s3")
    @patch("chimera_intel.core.data_pipeline.scrape_static_page")
    @patch("chimera_intel.core.data_pipeline.ascrape_dynamic_page", new_callable=AsyncMock)
    def test_cli_ingest_dynamic(
        self,
        mock_scrape_dynamic,
        mock_scrape_static,
        mock_upload_s3,
        mock_log_pg,
        mock_index_es,
    ):
        """Tests the 'pipeline ingest' CLI command for a dynamic page."""
        # Arrange
        # We patch ascrape_dynamic_page with an AsyncMock
        mock_scrape_dynamic.return_value = (self.mock_html_content, "Example")
        mock_upload_s3.return_value = f"raw_pages/{self.mock_hash}.html"
        mock_log_pg.return_value = 1
        mock_index_es.return_value = self.mock_hash

        # Need to patch asyncio.run to just return the mock's result
        with patch("chimera_intel.core.data_pipeline.asyncio.run", return_value=(self.mock_html_content, "Example")):
            # Act
            result = self.runner.invoke(
                pipeline_app, ["ingest", self.test_url, "--dynamic"]
            )
        
        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Ingestion Complete", result.stdout)
        self.assertIn(f'"url": "{self.test_url}"', result.stdout)
        self.assertIn('"status": "SUCCESS"', result.stdout)

        mock_scrape_static.assert_not_called()
        # We can't easily assert the call on the async mock inside asyncio.run
        # but we can check that the *other* mock wasn't called.
        mock_upload_s3.assert_called_once()
        mock_log_pg.assert_called_once()
        mock_index_es.assert_called_once()


    @patch("chimera_intel.core.data_pipeline.scrape_static_page", side_effect=Exception("Scrape Failed"))
    def test_pipeline_task_failure(self, mock_scrape_static):
        """Tests that the Celery task catches exceptions and reports FAILED."""
        
        result = self.runner.invoke(
            pipeline_app, ["ingest", self.test_url]
        )
        
        self.assertEqual(result.exit_code, 0) # CLI handles the error
        self.assertIn('"status": "FAILED"', result.stdout)
        self.assertIn("Scrape Failed", result.stdout)

if __name__ == "__main__":
    unittest.main()