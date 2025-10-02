import unittest
import os
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.user_manager import (
    get_password_hash,
    verify_password,
    set_active_user,
    get_active_user,
    logout_user,
    user_app,
    USER_CONTEXT_FILE,
)
from chimera_intel.core.schemas import User

runner = CliRunner()


class TestUserManager(unittest.TestCase):
    """Test cases for the user_manager module."""

    def setUp(self):
        """Clean up context file before each test."""
        if os.path.exists(USER_CONTEXT_FILE):
            os.remove(USER_CONTEXT_FILE)

    def tearDown(self):
        """Clean up context file after each test."""
        if os.path.exists(USER_CONTEXT_FILE):
            os.remove(USER_CONTEXT_FILE)

    def test_password_hashing_and_verification(self):
        """Tests that password hashing and verification work correctly without truncation."""
        # This password is longer than 72 bytes to test that Argon2 handles it correctly

        password = "a_very_long_and_secure_password_that_would_definitely_fail_with_the_bcrypt_limit_of_72_bytes"
        hashed_password = get_password_hash(password)
        self.assertTrue(verify_password(password, hashed_password))
        self.assertFalse(verify_password("wrong_password", hashed_password))

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    def test_get_active_user(self, mock_get_user_from_db):
        """Tests retrieving the active user."""
        set_active_user("testuser")
        mock_get_user_from_db.return_value = User(
            id=1, username="testuser", hashed_password="hashed_password"
        )

        user = get_active_user()

        self.assertIsNotNone(user)
        self.assertEqual(user.username, "testuser")
        mock_get_user_from_db.assert_called_with("testuser")

    def test_logout_user(self):
        """Tests logging out a user."""
        set_active_user("testuser")
        self.assertTrue(os.path.exists(USER_CONTEXT_FILE))
        logout_user()
        self.assertFalse(os.path.exists(USER_CONTEXT_FILE))

    @patch("chimera_intel.core.user_manager.create_user_in_db")
    @patch("chimera_intel.core.user_manager.get_user_from_db")
    def test_cli_add_user(self, mock_get_user, mock_create_user):
        """Tests the 'user add' CLI command."""
        mock_get_user.return_value = None
        # Use `input` to provide the password to the prompt

        result = runner.invoke(
            user_app, ["add", "newuser"], input="password\npassword\n"
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully created user 'newuser'", result.stdout)
        mock_create_user.assert_called_once()

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    def test_cli_add_user_already_exists(self, mock_get_user):
        """Tests adding a user that already exists."""
        mock_get_user.return_value = User(
            id=1, username="existinguser", hashed_password=""
        )
        result = runner.invoke(
            user_app, ["add", "existinguser"], input="password\npassword\n"
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("User 'existinguser' already exists", result.stdout)

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    @patch("chimera_intel.core.user_manager.verify_password", return_value=True)
    def test_cli_login_success(self, mock_verify, mock_get_user):
        """Tests the 'user login' CLI command with correct credentials."""
        mock_get_user.return_value = User(
            id=1, username="testuser", hashed_password="hashed_password"
        )
        result = runner.invoke(user_app, ["login", "testuser"], input="password\n")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully logged in as 'testuser'", result.stdout)

    @patch("chimera_intel.core.user_manager.get_user_from_db")
    @patch("chimera_intel.core.user_manager.verify_password", return_value=False)
    def test_cli_login_failure(self, mock_verify, mock_get_user):
        """Tests the 'user login' CLI command with incorrect credentials."""
        mock_get_user.return_value = User(
            id=1, username="testuser", hashed_password="hashed_password"
        )
        result = runner.invoke(user_app, ["login", "testuser"], input="wrongpassword\n")
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid username or password", result.stdout)

    def test_cli_logout(self):
        """Tests the 'user logout' CLI command."""
        set_active_user("testuser")
        result = runner.invoke(user_app, ["logout"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully logged out", result.stdout)
        self.assertFalse(os.path.exists(USER_CONTEXT_FILE))

    @patch("chimera_intel.core.user_manager.get_active_user")
    def test_cli_status_logged_in(self, mock_get_active_user):
        """Tests the 'user status' command when a user is logged in."""
        mock_get_active_user.return_value = User(
            id=1, username="testuser", hashed_password=""
        )
        result = runner.invoke(user_app, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Logged in as: testuser", result.stdout)

    @patch("chimera_intel.core.user_manager.get_active_user", return_value=None)
    def test_cli_status_logged_out(self, mock_get_active_user):
        """Tests the 'user status' command when no user is logged in."""
        result = runner.invoke(user_app, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Not logged in", result.stdout)


if __name__ == "__main__":
    unittest.main()
