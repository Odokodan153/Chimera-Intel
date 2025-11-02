import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from typer.testing import CliRunner
import typer
import asyncio

from chimera_intel.core.connect import connect_app

# Create a test app instance and add the connect_app
app = typer.Typer()
app.add_typer(connect_app)

runner = CliRunner()

class TestConnect(unittest.TestCase):
    """Test cases for the Connect module."""

    @patch("chimera_intel.core.connect.save_scan_to_db")
    @patch("chimera_intel.core.connect.API_KEYS")
    def test_messaging_scrapper_success(self, mock_api_keys, mock_save_db):
        """
        Tests the 'connect messaging-scrapper' command with mocked clients.
        """
        # --- Setup Mocks ---
        mock_api_keys.telegram_api_id = "test_id"
        mock_api_keys.telegram_api_hash = "test_hash"
        mock_api_keys.discord_bot_token = "test_token"

        # 1. Mock Telethon's TelegramClient
        # Mock the message object
        mock_tele_message = MagicMock()
        mock_tele_message.id = 123
        mock_tele_message.sender_id = 456
        mock_tele_message.text = "I found info on target-company"

        # Mock the async iterator
        async def async_iter_messages(*args, **kwargs):
            yield mock_tele_message

        # Mock the client instance
        mock_tele_client_instance = AsyncMock()
        mock_tele_client_instance.get_entity.return_value = MagicMock(title="Test Channel")
        mock_tele_client_instance.iter_messages.return_value = async_iter_messages()
        mock_tele_client_instance.__aenter__.return_value = mock_tele_client_instance # For 'async with'
        
        # Mock the client class
        mock_tele_client_class = MagicMock(return_value=mock_tele_client_instance)

        # 2. Mock Discord's SearchBot
        mock_bot_instance = AsyncMock()
        mock_bot_instance.results = [{
            "platform": "Discord", 
            "message": "discord info on target-company",
            "server": "Test Server", "channel": "test", "author": "bot", "url": "http://discord.com"
        }]
        
        # Mock the bot class
        mock_bot_class = MagicMock(return_value=mock_bot_instance)

        # --- Run Command with Patches ---
        with patch("chimera_intel.core.connect.TelegramClient", new=mock_tele_client_class), \
             patch("chimera_intel.core.connect.SearchBot", new=mock_bot_class):
            
            result = runner.invoke(
                app, 
                [
                    "connect", 
                    "messaging-scrapper", 
                    "target-company", 
                    "--telegram-channel", "test_channel",
                    "--discord-channel", "123456789"
                ]
            )

            # --- Assertions ---
            self.assertEqual(result.exit_code, 0)
            
            # Check that it reported success
            self.assertIn("Starting messaging scrape for target: target-company", result.stdout)
            self.assertIn("Success: Found 2 total mentions.", result.stdout)
            
            # Check that the output JSON is correct
            self.assertIn('"platform": "Telegram"', result.stdout)
            self.assertIn("I found info on target-company", result.stdout)
            self.assertIn('"platform": "Discord"', result.stdout)
            self.assertIn("discord info on target-company", result.stdout)
            self.assertIn('"total_mentions": 2', result.stdout)

            # Check that it saved to DB
            mock_save_db.assert_called_once()
            
            # Check that clients were called correctly
            mock_tele_client_class.assert_called_with(
                "chimera_intel.session", 
                "test_id", 
                "test_hash"
            )
            mock_bot_class.assert_called_once()
            # Check discord bot was started
            mock_bot_instance.start.assert_called_with("test_token")


    @patch("chimera_intel.core.connect.save_scan_to_db")
    @patch("chimera_intel.core.connect.API_KEYS")
    def test_messaging_scrapper_no_keys(self, mock_api_keys, mock_save_db):
        """
        Tests that the command skips modules if keys are not set.
        """
        # --- Setup Mocks ---
        mock_api_keys.telegram_api_id = None
        mock_api_keys.telegram_api_hash = None
        mock_api_keys.discord_bot_token = None
        
        # --- Run Command ---
        # We must still provide channels, or it will fail the "no channels" check
        result = runner.invoke(
            app, 
            [
                "connect", 
                "messaging-scrapper", 
                "target-company", 
                "-tc", "test", 
                "-dc", "123"
            ]
        )

        # --- Assertions ---
        self.assertEqual(result.exit_code, 0)
        
        # Check that it skipped all modules
        self.assertIn("Telegram: SKIPPED", result.stdout)
        self.assertIn("Discord: SKIPPED", result.stdout)
        
        # Check that it reported no mentions
        self.assertIn("No mentions found for this target.", result.stdout)
        self.assertIn('"total_mentions": 0', result.stdout)
        mock_save_db.assert_called_once()

    def test_messaging_scrapper_no_target(self):
        """
        Tests that the command fails if no target is provided.
        """
        result = runner.invoke(app, ["connect", "messaging-scrapper"])
        
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Missing argument 'TARGET'", result.stderr)
        
    def test_messaging_scrapper_no_channels_provided(self):
        """
        Tests that the command fails if no channels are provided.
        """
        result = runner.invoke(app, ["connect", "messaging-scrapper", "target-company"])
        
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Error: You must provide at least one", result.stdout)


if __name__ == "__main__":
    unittest.main()