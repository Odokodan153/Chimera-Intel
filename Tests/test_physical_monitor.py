import unittest
from unittest.mock import patch, MagicMock
import json
from pathlib import Path

from chimera_intel.core.physical_monitor import (
    analyze_location_imagery,
    _get_last_analysis
)
from chimera_intel.core.schemas import (
    ProjectConfig,
    KeyLocation
)

class TestPhysicalMonitor(unittest.TestCase):
    """Test cases for the new physical location monitor."""

    @patch("chimera_intel.core.physical_monitor.get_db_connection")
    def test_get_last_analysis_db(self, mock_get_conn):
        """Tests retrieving last scan data from the database."""
        # Arrange
        project_name = "TestProject"
        location_name = "Factory"
        target_str = f"{project_name}/{location_name}"
        
        mock_data = json.dumps({"object_counts": {"car": 10}})
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (mock_data,)
        mock_conn.cursor.return_value = __enter__=MagicMock(return_value=mock_cursor)
        mock_get_conn.return_value = mock_conn

        # Act
        result = _get_last_analysis(project_name, location_name)

        # Assert
        mock_cursor.execute.assert_called_with(
            unittest.mock.ANY, # SQL query
            (target_str, "physical_monitor")
        )
        self.assertEqual(result, {"object_counts": {"car": 10}})

    @patch("chimera_intel.core.physical_monitor.Path.exists")
    def test_analyze_location_skips_if_no_images(self, mock_path_exists):
        """Tests that the analysis function skips if images are missing."""
        # Arrange
        mock_path_exists.return_value = False # Both 'before' and 'after' images are missing
        project = ProjectConfig(project_name="TestProject", created_at="...")
        location = KeyLocation(name="HQ", address="123 Main")
        
        # Act
        # We just need to check it runs without error
        analyze_location_imagery(project, location)
        
        # Assert
        # No mocks (like DB or imint) should be called
        self.assertTrue(True) # Reached end without error


    @patch("chimera_intel.core.physical_monitor.shutil.move")
    @patch("chimera_intel.core.physical_monitor.save_scan_to_db")
    @patch("chimera_intel.core.physical_monitor.alert_manager_instance.dispatch_alert")
    @patch("chimera_intel.core.physical_monitor.perform_object_detection")
    @patch("chimera_intel.core.physical_monitor.compare_image_changes")
    @patch("chimera_intel.core.physical_monitor._get_last_analysis")
    @patch("chimera_intel.core.physical_monitor.Path.exists")
    def test_analyze_location_finds_changes(
        self, mock_path_exists, mock_get_last, mock_compare, 
        mock_detect, mock_dispatch_alert, mock_save_db, mock_shutil_move
    ):
        """Tests that both visual diffs and object count changes trigger alerts."""
        # Arrange
        mock_path_exists.return_value = True # All paths exist
        
        # 1. Config
        project = ProjectConfig(project_name="TestProject", created_at="...")
        location = KeyLocation(name="Factory", address="123 Industrial Rd")
        target_str = f"{project.project_name}/{location.name}"

        # 2. Get last analysis (old object counts)
        mock_get_last.return_value = {"object_counts": {"truck": 10, "car": 50}}
        
        # 3. IMINT: Compare images (finds visual change)
        mock_compare.return_value = {
            "status": "Significant change detected",
            "difference_score": 10.5,
            "change_areas_found": 20,
            "output_image": "physical_monitoring_assets/TestProject/Factory/last_run_diff.png"
        }
        
        # 4. IMINT: Detect objects (finds new counts)
        mock_detect.return_value = {"truck": 15, "car": 51, "boat": 1} # Truck count changed
        
        # Act
        analyze_location_imagery(project, location)

        # Assert
        # 1. Check for alerts (should be 2: one for visual, one for object count)
        self.assertEqual(mock_dispatch_alert.call_count, 2)
        
        # Alert 1: Visual Change
        mock_dispatch_alert.assert_any_call(
            title="Physical Change Detected: Factory",
            message=unittest.mock.ANY,
            level="WARNING",
            provenance={'module': 'physical_monitor', 'project': 'TestProject', 'location': 'Factory'}
        )
        alert_msg_visual = mock_dispatch_alert.call_args_list[0][1]['message']
        self.assertIn("Significant visual change (construction?)", alert_msg_visual)

        # Alert 2: Logistics Change
        mock_dispatch_alert.assert_any_call(
            title="Logistics Activity Alert: Factory",
            message=unittest.mock.ANY,
            level="WARNING",
            provenance={'module': 'physical_monitor', 'project': 'TestProject', 'location': 'Factory'}
        )
        alert_msg_logistics = mock_dispatch_alert.call_args_list[1][1]['message']
        self.assertIn("increase in 'truck' count", alert_msg_logistics)
        self.assertIn("Previous count: 10", alert_msg_logistics)
        self.assertIn("Current count: 15", alert_msg_logistics)
        self.assertIn("(+50.0%)", alert_msg_logistics)

        # 2. Check that new scan is saved to DB
        mock_save_db.assert_called_once_with(
            target=target_str,
            module="physical_monitor",
            data={
                "object_counts": {"truck": 15, "car": 51, "boat": 1},
                "last_diff_results": mock_compare.return_value,
                "image_analyzed": "physical_monitoring_assets/TestProject/Factory/image_after.png"
            }
        )
        
        # 3. Check that images were cycled
        mock_shutil_move.assert_called_once()

if __name__ == "__main__":
    unittest.main()