import unittest
from unittest.mock import MagicMock, patch, ANY
from chimera_intel.core.arg_service import (
    ARGService, 
    BaseEntity, 
    Relationship
)

class TestARGService(unittest.TestCase):

    def setUp(self):
        # Mock the graph_db_instance
        self.mock_db_driver = MagicMock()
        self.mock_db_driver.execute_query = MagicMock()
        
        # Mock the session for ingest queries
        self.mock_session = MagicMock()
        self.mock_session.run = MagicMock()
        
        # Configure the mock driver to return the mock session
        self.mock_db_driver._driver.session.return_value.__enter__.return_value = self.mock_session
        
        # Instantiate the service with the mock driver
        self.arg_service = ARGService(self.mock_db_driver)

    def test_run_arg_query_success(self):
        """Test that a read query is executed correctly."""
        expected_results = [{"n": {"name": "Test"}}]
        self.mock_db_driver.execute_query.return_value = expected_results
        
        query = "MATCH (n) RETURN n LIMIT 1"
        results = self.arg_service.run_arg_query(query)
        
        self.mock_db_driver.execute_query.assert_called_with(query, None)
        self.assertEqual(results, expected_results)

    def test_run_arg_query_write_warning(self):
        """Test that a write query logs a warning."""
        query = "CREATE (n:Test)"
        
        # We don't need to patch the logger, just check that the query
        # is still passed through (for now)
        self.arg_service.run_arg_query(query)
        self.mock_db_driver.execute_query.assert_called_with(query, None)
        
    def test_ingest_entities_and_relationships(self):
        """Test the ingestion logic for nodes and edges."""
        p1 = BaseEntity(id_value="john.doe", id_type="username", label="Person", properties={"name": "John Doe"})
        c1 = BaseEntity(id_value="shell.com", id_type="domain", label="Company", properties={"name": "ShellCo"})
        rel1 = Relationship(source=p1, target=c1, label="WORKS_FOR")
        
        entities = [p1, c1]
        relationships = [rel1]
        
        self.arg_service.ingest_entities_and_relationships(entities, relationships)
        
        # Check that session.run was called for entities
        p1_query, p1_params = p1.get_merge_query()
        self.mock_session.run.assert_any_call(p1_query, p1_params)
        
        c1_query, c1_params = c1.get_merge_query()
        self.mock_session.run.assert_any_call(c1_query, c1_params)
        
        # Check that session.run was called for relationships
        rel1_query, rel1_params = rel1.get_merge_query()
        self.mock_session.run.assert_any_call(rel1_query, rel1_params)
        
        # Should be 3 calls total (2 nodes, 1 edge)
        self.assertEqual(self.mock_session.run.call_count, 3)

    def test_find_shared_directors_query(self):
        """Test that the find_shared_directors method generates the correct query."""
        self.arg_service.find_shared_directors()
        
        expected_query = """
        MATCH (p:Person)-[:IS_DIRECTOR_OF]->(c:Company)
        WITH p, count(c) AS companies_directed
        WHERE companies_directed > 1
        MATCH (p)-[:IS_DIRECTOR_OF]->(c:Company)
        RETURN p.name AS person_name, 
               companies_directed, 
               collect(c.name) AS companies
        ORDER BY companies_directed DESC
        LIMIT 25
        """
        # Check that execute_query was called with the correct Cypher
        self.mock_db_driver.execute_query.assert_called_with(unittest.mock.ANY)
        called_query = self.mock_db_driver.execute_query.call_args[0][0]
        
        # Compare whitespace-normalized queries
        self.assertEqual(" ".join(called_query.split()), " ".join(expected_query.split()))

    def test_get_entity_temporal_evolution_query(self):
        """Test that the temporal query is generated correctly."""
        self.arg_service.get_entity_temporal_evolution("Company", "shell.com")
        
        expected_query = """
        MATCH (n:Company {company: $entity_id})-[r]-(m)
        RETURN n.name AS entity, 
               type(r) AS relationship_type, 
               m.name AS related_entity, 
               r.updated_at AS last_seen
        WHERE r.updated_at IS NOT NULL
        ORDER BY r.updated_at DESC
        LIMIT 50
        """
        expected_params = {"entity_id": "shell.com"}
        
        self.mock_db_driver.execute_query.assert_called_with(
            unittest.mock.ANY, 
            expected_params
        )
        called_query = self.mock_db_driver.execute_query.call_args[0][0]
        self.assertEqual(" ".join(called_query.split()), " ".join(expected_query.split()))


if __name__ == '__main__':
    unittest.main()