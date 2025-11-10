import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from datetime import datetime
from pathlib import Path
import psycopg2
# Import original functions
from chimera_intel.core.humint import (
    add_humint_source,
    add_humint_report,
    analyze_humint_reports,
    humint_app,
)
# (NEW) Import User for mocking
from chimera_intel.core.schemas import AiCoreResult, HumintNetworkLink, User

# Import NEW functions and models for MVP
from chimera_intel.core.humint import (
    register_source,
    submit_field_report,
    map_network_link,
    FieldReportIntake,
    validate_report,
    find_entity_links,
    get_source_details # (NEW)
)

runner = CliRunner()


class TestHumint(unittest.TestCase):
    """(Original) Test cases for the Human Intelligence (HUMINT) module."""

    # --- Original Function Tests ---

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_source_success(self, mock_get_conn):
        """Tests successfully adding a new HUMINT source."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        add_humint_source("ALPHA", "A1", "Cybercrime")

        mock_cursor.execute.assert_called_once_with(
            "INSERT INTO humint_sources (name, reliability, expertise) VALUES (%s, %s, %s)",
            ("ALPHA", "A1", "Cybercrime"),
        )
        mock_conn.commit.assert_called_once()

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_report_success(self, mock_get_conn):
        """Tests successfully adding a new HUMINT report."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)  # (source_id,)
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        add_humint_report("ALPHA", "Target is planning a new product launch.")

        mock_cursor.execute.assert_any_call(
            "SELECT id FROM humint_sources WHERE name = %s", ("ALPHA",)
        )
        mock_cursor.execute.assert_any_call(
            "INSERT INTO humint_reports (source_id, content) VALUES (%s, %s)",
            (1, "Target is planning a new product launch."),
        )
        mock_conn.commit.assert_called_once()

    @patch("chimera_intel.core.humint.get_db_connection")
    def test_add_humint_report_source_not_found(self, mock_get_conn):
        """Tests adding a report when the specified source does not exist."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        add_humint_report("BETA", "Some report content.")

        insert_calls = [
            call
            for call in mock_cursor.execute.call_args_list
            if "INSERT" in call[0][0]
        ]
        self.assertEqual(len(insert_calls), 0)
        mock_conn.commit.assert_not_called()

    @patch("chimera_intel.core.humint.generate_swot_from_data")
    @patch("chimera_intel.core.humint.get_db_connection")
    @patch("chimera_intel.core.humint.API_KEYS")
    def test_analyze_humint_reports_success(
        self, mock_api_keys, mock_get_conn, mock_gen_swot
    ):
        """Tests successful AI analysis of HUMINT reports."""
        mock_api_keys.google_api_key = "fake_key"
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("ALPHA", "A1", "Report content about topic.")
        ]
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_gen_swot.return_value = AiCoreResult(analysis_text="AI Summary Text")

        result = analyze_humint_reports("topic")

        self.assertEqual(result, "AI Summary Text")
        mock_gen_swot.assert_called_once()
        prompt_arg = mock_gen_swot.call_args[0][0]
        self.assertIn("Report content about topic.", prompt_arg)

    # --- Original CLI Tests ---

    @patch("chimera_intel.core.humint.add_humint_source")
    def test_cli_add_source(self, mock_add_source):
        """Tests the 'humint add-source' CLI command."""
        result = runner.invoke(
            humint_app,
            [
                "add-source",
                "--name", "CHARLIE",
                "--reliability", "B2",
                "--expertise", "Finance",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        mock_add_source.assert_called_once_with("CHARLIE", "B2", "Finance")

    @patch("chimera_intel.core.humint.add_humint_report")
    def test_cli_add_report(self, mock_add_report):
        """Tests the 'humint add-report' CLI command."""
        result = runner.invoke(
            humint_app,
            ["add-report", "--source", "ALPHA", "--content", "New intel"],
            input="New intel\n" # For prompt
        )
        self.assertEqual(result.exit_code, 0)
        mock_add_report.assert_called_once_with("ALPHA", "New intel")

    @patch("chimera_intel.core.humint.analyze_humint_reports")
    def test_cli_analyze(self, mock_analyze):
        """Tests the 'humint analyze' CLI command."""
        mock_analyze.return_value = "AI-Powered Analysis"
        result = runner.invoke(humint_app, ["analyze", "acquisition"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("AI-Powered Analysis", result.stdout)
        mock_analyze.assert_called_once_with("acquisition")

    @patch("chimera_intel.core.humint.API_KEYS", MagicMock(google_api_key="test_key"))
    @patch("chimera_intel.core.humint.generate_swot_from_data")
    def test_cli_simulate_social(self, mock_generate_swot):
        """Tests the simulate-social CLI command."""
        mock_response_text = "Operative: Hello!\nTarget: Hi.\n[SIMULATION SUMMARY] The simulation was short."
        mock_ai_result = AiCoreResult(analysis_text=mock_response_text, error=None)
        mock_generate_swot.return_value = mock_ai_result
        
        result = runner.invoke(
            humint_app,
            [
                "simulate-social",
                "--target", "A disgruntled network engineer.",
                "--goal", "Find out what firewall they use."
            ]
        )
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("INITIATING VIRTUAL HUMINT SIMULATION", result.stdout)
        self.assertIn("Virtual HUMINT Simulation Log", result.stdout)


# --- (NEW) MVP (PRACTICAL ROADMAP) TESTS ---

# (NEW) Mock TextBlob before it's imported by humint
mock_textblob = MagicMock()
mock_textblob.return_value.noun_phrases = ["Auto Entity", "Manual Entity"]
# (NEW) Mock User object for role-based tests
mock_admin_user = User(username="admin", role="Administrator", full_name="Admin", email="a@b.com", disabled=False, hashed_password="x")
mock_analyst_user = User(username="analyst", role="Analyst", full_name="Analyst", email="a@b.com", disabled=False, hashed_password="x")


@patch("chimera_intel.core.humint.NLP_AVAILABLE", True)
@patch("chimera_intel.core.humint.TextBlob", mock_textblob)
@patch("chimera_intel.core.humint.psycopg2.extras") # Mock json adapter
@patch("chimera_intel.core.humint.datetime")
@patch("chimera_intel.core.humint.security_utils") # Mock the imported module
@patch("chimera_intel.core.humint.get_db_connection")
@patch("chimera_intel.core.humint.get_vault") # (NEW) Mock Forensic Vault
class TestHumintMVP(unittest.TestCase):
    """(NEW) Test cases for the new practical HUMINT roadmap features."""

    def test_register_source_success(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """Tests successfully registering a new source with (mocked) encryption."""
        # Arrange
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        mock_security.encrypt_pii.side_effect = [b"encrypted-contact-bytes", b"encrypted-payment-bytes"]
        mock_datetime.now.return_value = datetime(2025, 1, 1)

        # Act
        register_source(
            name="EXPERT-001",
            contact_info="user@example.com",
            expertise="Supply Chain",
            initial_reliability="B2",
            consent_status="Signed",
            consent_artifact_path="/docs/consent-001.pdf",
            payment_details="bank-info"
        )

        # Assert
        mock_security.encrypt_pii.assert_any_call("user@example.com")
        mock_security.encrypt_pii.assert_any_call("bank-info")
        mock_cursor.execute.assert_called_once_with(
            unittest.mock.ANY, # The SQL string
            (
                "EXPERT-001", "B2", "Supply Chain", b"encrypted-contact-bytes",
                b"encrypted-payment-bytes", "Signed", "/docs/consent-001.pdf", 
                datetime(2025, 1, 1)
            )
        )
        mock_conn.commit.assert_called_once()

    # (MODIFIED) This test now checks auto-extraction and vault logging
    @patch("chimera_intel.core.humint._extract_and_link_entities")
    def test_submit_field_report_full_pipeline(self, mock_extract, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """(UPDATED) Tests submitting a report, logging to vault, and calling auto-extraction."""
        # Arrange
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [(1,), (42,)] # (source_id,), (new_report_id,)
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_datetime.now.return_value = datetime(2025, 1, 1)
        mock_json = MagicMock()
        mock_psycopg_extras.Json.return_value = mock_json
        
        mock_vault = mock_get_vault.return_value # Get the mock vault instance
        
        mock_extract.return_value = ["Manual Entity", "Auto Entity"]

        intake = FieldReportIntake(
            report_type="Interview",
            content="Report about Manual Entity and Auto Entity.",
            entities_mentioned=["Manual Entity"],
            tags=["tag1"],
            metadata={"location": "Virtual"}
        )

        # Act
        new_id = submit_field_report("EXPERT-001", intake)

        # Assert
        self.assertEqual(new_id, 42)
        
        # 1. Check report insertion
        mock_cursor.execute.assert_any_call(
            unittest.mock.ANY, # INSERT string
            (1, "Report about Manual Entity and Auto Entity.", "Interview",
             ["tag1"], mock_json, datetime(2025, 1, 1))
        )
        
        # 2. (NEW) Check Forensic Vault logging
        expected_metadata = {
            "source_name": "EXPERT-001",
            "report_id": 42,
            "report_type": "Interview",
            "tags": ["tag1"],
        }
        mock_vault.store_evidence.assert_called_once_with(
            content=b"Report about Manual Entity and Auto Entity.",
            content_type="text/plain",
            file_name="humint_report_42.txt",
            metadata=expected_metadata
        )
        
        # 3. Check entity extraction call
        mock_extract.assert_called_once_with(
            report_id=42,
            source_name="EXPERT-001",
            content="Report about Manual Entity and Auto Entity.",
            manual_entities=["Manual Entity"]
        )
        
        # 4. Check report UPDATE with final entities
        mock_cursor.execute.assert_any_call(
            "UPDATE humint_reports SET entities = %s WHERE id = %s",
            (["Manual Entity", "Auto Entity"], 42)
        )
        mock_conn.commit.assert_called_once()

    def test_map_network_link_success(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """Tests mapping a human network link."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_datetime.now.return_value = datetime(2025, 1, 1)

        map_network_link("Person A", "Mentored", "Person B", 42)

        mock_cursor.execute.assert_called_once_with(
            unittest.mock.ANY, # The SQL INSERT string
            ("Person A", "Mentored", "Person B", 42, datetime(2025, 1, 1))
        )
        mock_conn.commit.assert_called_once()

    def test_validate_report_with_reliability_update(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """Tests the validation workflow including a reliability update."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_datetime.now.return_value = datetime(2025, 1, 1)
        mock_cursor.fetchone.return_value = (1,) 

        validate_report(42, "Confirmed", "Cross-verified.", "j.doe", "B1")

        mock_cursor.execute.assert_any_call(
            unittest.mock.ANY, # INSERT INTO humint_validation_logs...
            (42, "Confirmed", "Cross-verified.", "j.doe", datetime(2025, 1, 1))
        )
        mock_cursor.execute.assert_any_call(
            "UPDATE humint_sources SET reliability = %s WHERE id = %s", ("B1", 1)
        )
        mock_cursor.execute.assert_any_call(
            unittest.mock.ANY, # INSERT INTO humint_reliability_logs...
            (1, "B1", "Validation of report 42: Cross-verified.", "j.doe", datetime(2025, 1, 1))
        )
        self.assertEqual(mock_conn.commit.call_count, 1)

    def test_find_entity_links_success(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """Tests finding network links from the DB."""
        mock_conn = MagicMock()
        mock_dict_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_dict_cursor
        mock_record = {
            "id": 1, "entity_a": "Person A", "relationship": "Worked with",
            "entity_b": "Person B", "source_report_id": 42, "created_on": datetime(2025, 1, 1)
        }
        mock_dict_cursor.fetchall.return_value = [mock_record]

        links = find_entity_links("Person A")

        mock_conn.cursor.assert_called_once_with(cursor_factory=psycopg2.extras.DictCursor)
        mock_dict_cursor.execute.assert_called_once_with(
            unittest.mock.ANY, ("%Person A%", "%Person A%")
        )
        self.assertEqual(len(links), 1)
        self.assertIsInstance(links[0], HumintNetworkLink)
        
    # --- (NEW) Access Control Tests ---
    
    def test_get_source_details_admin_access(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """(NEW) Tests that an Admin can see decrypted PII."""
        # Arrange
        mock_conn = MagicMock()
        mock_dict_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_dict_cursor
        
        mock_record = {
            "id": 1, "name": "EXPERT-001", "reliability": "A1", "expertise": "Finance",
            "consent_status": "Signed",
            "encrypted_contact": b"enc-contact",
            "encrypted_payment_details": b"enc-payment"
        }
        mock_dict_cursor.fetchone.return_value = mock_record
        mock_security.decrypt_pii.side_effect = ["plaintext-contact", "plaintext-payment"]
        
        # Act
        details = get_source_details("EXPERT-001", mock_admin_user)
        
        # Assert
        self.assertIsNotNone(details)
        mock_security.decrypt_pii.assert_any_call(b"enc-contact")
        mock_security.decrypt_pii.assert_any_call(b"enc-payment")
        self.assertEqual(details.contact_info, "plaintext-contact")
        self.assertEqual(details.payment_details, "plaintext-payment")

    def test_get_source_details_analyst_redacted(self, mock_get_vault, mock_get_conn, mock_security, mock_datetime, mock_psycopg_extras, *args):
        """(NEW) Tests that an Analyst sees redacted PII."""
        # Arrange
        mock_conn = MagicMock()
        mock_dict_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_dict_cursor
        
        mock_record = {
            "id": 1, "name": "EXPERT-001", "reliability": "A1", "expertise": "Finance",
            "consent_status": "Signed",
            "encrypted_contact": b"enc-contact",
            "encrypted_payment_details": b"enc-payment"
        }
        mock_dict_cursor.fetchone.return_value = mock_record
        
        # Act
        details = get_source_details("EXPERT-001", mock_analyst_user)
        
        # Assert
        self.assertIsNotNone(details)
        mock_security.decrypt_pii.assert_not_called() # Decryption should not happen
        self.assertEqual(details.contact_info, "[REDACTED]")
        self.assertEqual(details.payment_details, "[REDACTED]")

    # --- (NEW) CLI Tests for New Commands ---

    @patch("chimera_intel.core.humint.register_source")
    def test_cli_register_source(self, mock_register, *args):
        """Tests the 'humint register-source' CLI command."""
        result = runner.invoke(
            humint_app,
            ["register-source", "--name", "EXPERT-002", "--expertise", "Finance", "--reliability", "B2", "--consent", "Verbal"],
            input="test@test.com\nsecret-bank\n"
        )
        self.assertEqual(result.exit_code, 0)
        mock_register.assert_called_once_with(
            "EXPERT-002", "test@test.com", "Finance", "B2", "Verbal", None, "secret-bank"
        )

    @patch("chimera_intel.core.humint.submit_field_report")
    def test_cli_submit_report(self, mock_submit, *args):
        """Tests the 'humint submit-report' CLI command."""
        result = runner.invoke(
            humint_app,
            ["submit-report", "--source", "EXPERT-001", "--type", "Web", "--entity", "Org X", "--tag", "rumor"],
            input="Observed Org X online."
        )
        expected_intake = FieldReportIntake(
            report_type="Web", content="Observed Org X online.",
            entities_mentioned=["Org X"], tags=["rumor"], metadata={}
        )
        self.assertEqual(result.exit_code, 0)
        mock_submit.assert_called_once()
        self.assertEqual(mock_submit.call_args[0][0], "EXPERT-001")
        self.assertEqual(mock_submit.call_args[0][1], expected_intake)

    @patch("chimera_intel.core.humint.map_network_link")
    def test_cli_map_link(self, mock_map_link, *args):
        """Tests the 'humint map-link' CLI command."""
        result = runner.invoke(
            humint_app,
            ["map-link", "--from", "Alice", "--rel", "Worked at", "--to", "Globex Corp", "--report-id", "10"]
        )
        self.assertEqual(result.exit_code, 0)
        mock_map_link.assert_called_once_with("Alice", "Worked at", "Globex Corp", 10)

    @patch("chimera_intel.core.humint.validate_report")
    def test_cli_validate_report(self, mock_validate, *args):
        """Tests the 'humint validate-report' CLI command."""
        result = runner.invoke(
            humint_app,
            ["validate-report", "42", "--status", "Confirmed", "--analyst", "j.doe", "--update-reliability", "A1"],
            input="Looks solid.\n"
        )
        self.assertEqual(result.exit_code, 0)
        mock_validate.assert_called_once_with(
            42, "Confirmed", "Looks solid.", "j.doe", "A1"
        )

    @patch("chimera_intel.core.humint.find_entity_links")
    def test_cli_find_links(self, mock_find_links, *args):
        """Tests the 'humint find-links' CLI command."""
        mock_link = HumintNetworkLink(
            id=1, entity_a="Person A", relationship="Mentors",
            entity_b="Person B", source_report_id=10, created_on=datetime(2025, 1, 1)
        )
        mock_find_links.return_value = [mock_link]
        result = runner.invoke(humint_app, ["find-links", "Person A"])
        self.assertEqual(result.exit_code, 0)
        mock_find_links.assert_called_once_with("Person A")
        self.assertIn("Mentors", result.stdout)

    @patch("chimera_intel.core.humint.submit_field_report")
    @patch("chimera_intel.core.humint.transcribe_audio_report")
    @patch("chimera_intel.core.humint.SPEECH_RECOGNITION_AVAILABLE", True)
    def test_cli_submit_audio_report(self, mock_transcribe, mock_submit, *args):
        """Tests the 'submit-audio-report' CLI command."""
        mock_transcribe.return_value = "This is the transcribed text."
        with runner.isolated_filesystem():
            with open("test_audio.wav", "w") as f:
                f.write("dummy audio data")
            result = runner.invoke(
                humint_app,
                ["submit-audio-report", "--source", "EXPERT-001", "--file", "test_audio.wav", "--entity", "Project X"],
                input="y\n"
            )
        self.assertEqual(result.exit_code, 0)
        mock_transcribe.assert_called_once_with(Path("test_audio.wav"))
        expected_intake = FieldReportIntake(
            report_type="Audio Debrief", content="This is the transcribed text.",
            entities_mentioned=["Project X"], tags=["audio-transcription"],
            metadata={"original_audio_file": "test_audio.wav"}
        )
        mock_submit.assert_called_once()
        self.assertEqual(mock_submit.call_args[0][0], "EXPERT-001")
        self.assertEqual(mock_submit.call_args[0][1], expected_intake)

if __name__ == "__main__":
    unittest.main()