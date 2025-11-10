"""
(NEW) Tests for the ARG Fuser Module.
"""
import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

# Mock database connections before importing
mock_pg_conn = MagicMock()
mock_pg_cursor = MagicMock()
mock_get_db_connection = MagicMock(return_value=mock_pg_conn)
mock_pg_conn.cursor.return_value = mock_pg_cursor

mock_neo4j_graph = MagicMock()
mock_arg_service = MagicMock()
mock_arg_service.graph = mock_neo4j_graph
mock_get_arg_service = MagicMock(return_value=mock_arg_service)

MOCKS = {
    "chimera_intel.core.arg_fuser.get_db_connection": mock_get_db_connection,
    "chimera_intel.core.arg_fuser.get_arg_service": mock_get_arg_service,
}

with patch.dict("sys.modules", MOCKS):
    from chimera_intel.core.arg_fuser import fuse_humint_to_arg, arg_fuser_app

runner = CliRunner()

class TestArgFuser(unittest.TestCase):

    def setUp(self):
        # Reset all mocks before each test
        mock_pg_conn.reset_mock()
        mock_pg_cursor.reset_mock()
        mock_get_db_connection.reset_mock()
        mock_neo4j_graph.reset_mock()
        mock_arg_service.reset_mock()
        mock_get_arg_service.reset_mock()
        
        # Re-apply mocks
        mock_get_db_connection.return_value = mock_pg_conn
        mock_pg_conn.cursor.return_value = mock_pg_cursor
        mock_get_arg_service.return_value = mock_arg_service
        mock_arg_service.graph = mock_neo4j_graph

    def test_fuse_humint_to_arg_success(self):
        """Tests the full ARG fusion process."""
        
        # 1. Setup mock data from PostgreSQL
        mock_sources = [
            {"id": 1, "name": "SOURCE-001", "reliability": "A1", "expertise": "Finance", "registered_on": None}
        ]
        mock_reports = [
            {"id": 42, "report_type": "Interview", "reported_on": None, "entities": ["Person A"], "source_name": "SOURCE-001"}
        ]
        mock_links = [
            {"entity_a": "Person A", "relationship": "Worked At", "entity_b": "Globex", "source_report_id": 42}
        ]
        
        mock_pg_cursor.fetchall.side_effect = [
            mock_sources,
            mock_reports,
            mock_links
        ]
        
        # 2. Act
        counts = fuse_humint_to_arg()
        
        # 3. Assert
        self.assertEqual(counts, {"sources": 1, "reports": 1, "links": 1})
        
        # Check that the graph service was called correctly
        
        # Call for Source
        mock_neo4j_graph.create_node.assert_any_call(
            "HumintSource",
            properties={
                "name": "SOURCE-001",
                "reliability": "A1",
                "expertise": "Finance",
                "registered_on": None,
                "postgres_id": 1
            },
            unique_property="name"
        )
        
        # Call for Report
        mock_neo4j_graph.create_node.assert_any_call(
            "HumintReport",
            properties={
                "postgres_id": 42,
                "type": "Interview",
                "reported_on": None,
                "entities": ["Person A"]
            },
            unique_property="postgres_id"
        )
        
        # Call for relationship between Source and Report
        mock_neo4j_graph.create_relationship.assert_called_once_with(
            "HumintSource", "SOURCE-001", "name",
            "SUBMITTED",
            "HumintReport", 42, "postgres_id"
        )
        
        # Call for the network link (uses ArgService helper)
        mock_arg_service.add_relationship.assert_called_once_with(
            node_a_label="Entity",
            node_a_name="Person A",
            relationship_type="WORKED_AT", # Check that it was reformatted
            node_b_label="Entity",
            node_b_name="Globex",
            provenance="HUMINT Report 42"
        )
        
        # Check that connections were made and closed
        mock_get_db_connection.assert_called_once()
        mock_pg_conn.close.assert_called_once()

    def test_cli_sync_humint(self):
        """Tests the CLI command for syncing HUMINT."""
        
        # Just need to check that it calls the main function
        with patch("chimera_intel.core.arg_fuser.fuse_humint_to_arg") as mock_fuse:
            result = runner.invoke(arg_fuser_app, ["sync-humint"])
            
            self.assertEqual(result.exit_code, 0)
            mock_fuse.assert_called_once()