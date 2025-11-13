# Tests/test_mdm_engine.py

import unittest
from unittest.mock import MagicMock, call
from src.chimera_intel.core import mdm_engine
from src.chimera_intel.core.graph_db import GraphDB

class TestMDMEngine(unittest.TestCase):

    def setUp(self):
        # Mock the graph_db_instance
        self.mock_graph = MagicMock(spec=GraphDB)
        mdm_engine.graph_db_instance = self.mock_graph

        # Mock the scheduler
        self.mock_add_job = MagicMock()
        mdm_engine.add_job = self.mock_add_job

    def test_promote_attributes(self):
        master_props = {
            "id": "person-1",
            "label": "John Doe",
            "aliases": ["JD"],
            "url": "http://main.com",
            "rel_count": 5
        }
        dup_props = {
            "id": "person-2",
            "label": "Doe, John",
            "aliases": ["Johnny"],
            "url": "http://new.com",
            "new_prop": "value",
            "rel_count": 2
        }

        final_props = mdm_engine.promote_attributes(master_props, dup_props)

        # Keeps master's name
        self.assertEqual(final_props["label"], "John Doe")
        # Merges aliases and adds dup's name
        self.assertIn("JD", final_props["aliases"])
        self.assertIn("Johnny", final_props["aliases"])
        self.assertIn("Doe, John", final_props["aliases"])
        # Takes "newer" URL
        self.assertEqual(final_props["url"], "http://new.com")
        # Adds new property
        self.assertEqual(final_props["new_prop"], "value")
        # Adds metadata
        self.assertIn("mdm_merged_at", final_props)
        # Removes helper metadata
        self.assertNotIn("rel_count", final_props)

    def test_choose_master(self):
        # Test 1: More relationships wins
        n1 = {"id": "p1", "rel_count": 10}
        n2 = {"id": "p2", "rel_count": 5}
        master_id, dup_id, _, _ = mdm_engine.choose_master(n1, n2)
        self.assertEqual(master_id, "p1")
        self.assertEqual(dup_id, "p2")

        # Test 2: MasterEntity label wins
        n1 = {"id": "p1", "rel_count": 2, "labels": ["MasterEntity"]}
        n2 = {"id": "p2", "rel_count": 20}
        master_id, dup_id, _, _ = mdm_engine.choose_master(n1, n2)
        self.assertEqual(master_id, "p1")
        self.assertEqual(dup_id, "p2")

    def test_run_mdm_cycle(self):
        # 1. Mocks for find_duplicate_candidates
        candidates = [
            {
                "node1_id": "p1", "node2_id": "p2",
                "node1_name": "John Doe", "node2_name": "J. Doe",
                "shared_neighbors": 1
            }
        ]
        self.mock_graph.run_query.side_effect = [
            candidates, # For find_duplicate_candidates
            [{"properties": {"id": "p1", "label": "John Doe"}, "rel_count": 5}], # For get_node_details(p1)
            [{"properties": {"id": "p2", "label": "J. Doe"}, "rel_count": 2}], # For get_node_details(p2)
            [], # For query_set_props
            [{"rels_moved": 1}], # For relink_incoming
            [{"rels_moved": 1}], # For relink_outgoing
            [], # For delete_dup
            [], # For 'Company' type
            [], # For 'Organization' type
        ]
        
        # We need .single() for get_node_details
        mock_result_p1 = MagicMock()
        mock_result_p1.single.return_value = {"properties": {"id": "p1", "label": "John Doe"}, "rel_count": 5}
        mock_result_p2 = MagicMock()
        mock_result_p2.single.return_value = {"properties": {"id": "p2", "label": "J. Doe"}, "rel_count": 2}
        
        self.mock_graph.run_query.side_effect = [
            candidates,
            mock_result_p1,
            mock_result_p2,
            MagicMock(), # set_props
            MagicMock(), # relink_incoming
            MagicMock(), # relink_outgoing
            MagicMock(), # delete_dup
            [], # 'Company'
            [], # 'Organization'
        ]

        mdm_engine.run_mdm_cycle()

        # Check that the merge queries were called
        query_calls = self.mock_graph.run_query.call_args_list
        
        # Check SET properties query
        set_props_call = query_calls[3]
        self.assertIn("SET n = $props, n:MasterEntity", set_props_call.args[0])
        self.assertEqual(set_props_call.kwargs["master_id"], "p1")
        self.assertEqual(set_props_call.kwargs["props"]["label"], "John Doe")

        # Check relink incoming
        relink_in_call = query_calls[4]
        self.assertIn("apoc.refactor.from", relink_in_call.args[0])
        self.assertEqual(relink_in_call.kwargs["dup_id"], "p2")

        # Check relink outgoing
        relink_out_call = query_calls[5]
        self.assertIn("apoc.refactor.to", relink_out_call.args[0])
        self.assertEqual(relink_out_call.kwargs["dup_id"], "p2")

        # Check delete
        delete_call = query_calls[6]
        self.assertIn("DETACH DELETE dup", delete_call.args[0])
        self.assertEqual(delete_call.kwargs["dup_id"], "p2")

    def test_schedule_mdm_engine(self):
        cron_str = "0 1 * * *"
        mdm_engine.schedule_mdm_engine(cron_str)
        
        self.mock_add_job.assert_called_once_with(
            func=mdm_engine.run_mdm_cycle,
            trigger="cron",
            cron_schedule=cron_str,
            job_id="core_mdm_engine_cycle",
            kwargs={},
        )

if __name__ == "__main__":
    unittest.main()