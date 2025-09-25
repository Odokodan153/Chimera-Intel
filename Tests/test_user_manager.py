import unittest
import os
from unittest.mock import patch, mock_open
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.user_manager import (
    get_password_hash,
    verify_password,
    set_active_user,
    get_active_user,
    logout_user,
    USER_CONTEXT_FILE,
)
from chimera_intel.core.schemas import User

runner = CliRunner()


class TestUserManager(unittest.TestCase):
    """Test cases for the User Manager module."""

    def setUp(self):
        """Clean up any context files before each test."""
        if os.path.exists(USER_CONTEXT_FILE):
            os.remove(USER_CONTEXT_FILE)

    def tearDown(self):
        """Clean up any context files after each test."""
        if os.path.exists(USER_CONTEXT_FILE):
            os.remove(USER_CONTEXT_FILE)

    def test_password_hashing_and_verification(self):
        """Tests that password hashing and verification work correctly."""
        password = "correct_password"
        hashed_password = get_password_hash(password)
        self.assertTrue(verify_password(password, hashed_password))
        self.assertFalse(verify_password("wrong_password", hashed_password))

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    @patch("builtins.open", new_callable=mock_open)
    def test_set_and_get_active_user(self, mock_file, mock_get_user):
        """Tests setting and retrieving the active user context."""
        set_active_user("testuser")
        mock_file.assert_called_with(USER_CONTEXT_FILE, "w")
        mock_file().write.assert_called_with("testuser")

        mock_get_user.return_value = User(
            id=1, username="testuser", hashed_password="pw"
        )

        m = mock_open(read_data="testuser")
        with patch("builtins.open", m):
            active_user = get_active_user()
        self.assertIsNotNone(active_user)
        self.assertEqual(active_user.username, "testuser")

    def test_logout_user(self):
        """Tests that logging out removes the context file."""
        # Create a dummy context file to be deleted

        with open(USER_CONTEXT_FILE, "w") as f:
            f.write("testuser")
        logout_user()
        self.assertFalse(os.path.exists(USER_CONTEXT_FILE))

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.user_manager.get_user_from_db", return_value=None)
    @patch("chimera_intel.core.user_manager.create_user_in_db")
    def test_cli_user_add_success(self, mock_create_user, mock_get_user):
        """Tests the 'user add' CLI command."""
        result = runner.invoke(
            app, ["user", "add", "newuser", "--password", "password"]
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully created user 'newuser'", result.stdout)
        mock_create_user.assert_called_once()

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    @patch("chimera_intel.core.user_manager.verify_password", return_value=True)
    def test_cli_user_login_success(self, mock_verify, mock_get_user):
        """Tests the 'user login' CLI command."""
        mock_get_user.return_value = User(
            id=1, username="testuser", hashed_password="hashed_password"
        )
        result = runner.invoke(app, ["user", "login", "testuser"], input="password\n")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully logged in as 'testuser'", result.stdout)

    def test_cli_user_logout(self):
        """Tests the 'user logout' command."""
        # Create a dummy context file

        set_active_user("testuser")
        result = runner.invoke(app, ["user", "logout"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully logged out", result.stdout)
        self.assertFalse(os.path.exists(USER_CONTEXT_FILE))

    @patch("chimera_intel.core.user_manager.get_active_user")
    def test_cli_user_status(self, mock_get_active_user):
        """Tests the 'user status' command."""
        mock_get_active_user.return_value = User(
            id=1, username="testuser", hashed_password="pw"
        )
        result = runner.invoke(app, ["user", "status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Logged in as: testuser", result.stdout)


if __name__ == "__main__":
    unittest.main()
