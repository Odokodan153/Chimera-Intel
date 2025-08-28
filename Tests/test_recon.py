import unittest
from chimera_intel.core.recon import (
    find_credential_leaks,
    find_digital_assets,
    analyze_threat_infrastructure,
)


class TestRecon(unittest.TestCase):
    """Test cases for the advanced reconnaissance module."""

    def test_find_credential_leaks(self):
        """Tests the credential leak discovery function."""
        result = find_credential_leaks("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)
        self.assertTrue(result.compromised_credentials[0].is_plaintext)

    def test_find_digital_assets(self):
        """Tests the digital asset discovery function."""
        result = find_digital_assets("Example Corp")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.mobile_apps), 1)
        self.assertEqual(len(result.public_datasets), 1)
        self.assertIn("READ_CONTACTS", result.mobile_apps[0].permissions)

    def test_analyze_threat_infrastructure(self):
        """Tests the threat infrastructure analysis function."""
        result = analyze_threat_infrastructure("bad-domain.com")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.related_indicators), 2)
        self.assertEqual(result.related_indicators[1].value, "malicious-c2.net")


if __name__ == "__main__":
    unittest.main()
