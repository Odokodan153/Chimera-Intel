import pytest
import os
import json
from typer.testing import CliRunner
from chimera_intel.core.human_review_service import HumanReviewService, ReviewStatus, review_app, REVIEW_QUEUE_PATH

TEST_QUEUE_PATH = "test_review_queue.json"

@pytest.fixture
def test_service():
    """Fixture to create a HumanReviewService with a clean test queue."""
    if os.path.exists(TEST_QUEUE_PATH):
        os.remove(TEST_QUEUE_PATH)
    
    service = HumanReviewService(db_path=TEST_QUEUE_PATH)
    yield service
    
    if os.path.exists(TEST_QUEUE_PATH):
        os.remove(TEST_QUEUE_PATH)

@pytest.fixture
def cli_runner():
    return CliRunner()

def test_submit_for_review(test_service: HumanReviewService):
    """Test submitting a new action for review."""
    assert test_service.get_reviews(Status=ReviewStatus.PENDING) == []
    
    req = test_service.submit_for_review(
        user="test_user",
        action_name="red-team:phishing",
        target="example.com",
        justification="Client engagement"
    )
    
    assert req.user == "test_user"
    assert req.action_name == "red-team:phishing"
    assert req.status == ReviewStatus.PENDING
    
    pending = test_service.get_reviews(Status=ReviewStatus.PENDING)
    assert len(pending) == 1
    assert pending[0].id == req.id

def test_approve_request(test_service: HumanReviewService):
    """Test approving a pending request."""
    req = test_service.submit_for_review("user1", "action1", "target1")
    assert test_service.get_reviews(Status=ReviewStatus.PENDING)[0].id == req.id
    
    approved_req = test_service.approve_request(req.id, "reviewer_admin")
    assert approved_req is not None
    assert approved_req.id == req.id
    assert approved_req.status == ReviewStatus.APPROVED
    assert approved_req.reviewer == "reviewer_admin"
    
    assert test_service.get_reviews(Status=ReviewStatus.PENDING) == []
    assert len(test_service._load_queue()) == 1 # Still in the DB, just status changed

def test_deny_request(test_service: HumanReviewService):
    """Test denying a pending request."""
    req = test_service.submit_for_review("user2", "action2", "target2")
    
    denied_req = test_service.deny_request(req.id, "reviewer_admin")
    assert denied_req is not None
    assert denied_req.status == ReviewStatus.DENIED
    assert denied_req.reviewer == "reviewer_admin"
    
    assert test_service.get_reviews(Status=ReviewStatus.PENDING) == []

def test_cli_approve_deny(cli_runner: CliRunner, test_service: HumanReviewService):
    """Test the 'review approve' and 'review deny' CLI commands."""
    from chimera_intel.core import human_review_service
    human_review_service.review_service_instance = test_service
    
    req1 = test_service.submit_for_review("u1", "a1", "t1")
    req2 = test_service.submit_for_review("u2", "a2", "t2")
    
    # Test list
    result_list = cli_runner.invoke(review_app, ["list"])
    assert result_list.exit_code == 0
    assert req1.id in result_list.stdout
    assert req2.id in result_list.stdout
    
    # Test approve
    result_approve = cli_runner.invoke(review_app, ["approve", req1.id, "--user", "admin"])
    assert result_approve.exit_code == 0
    assert "APPROVED" in result_approve.stdout
    
    # Test deny
    result_deny = cli_runner.invoke(review_app, ["deny", req2.id, "--user", "admin"])
    assert result_deny.exit_code == 0
    assert "DENIED" in result_deny.stdout
    
    # Test list is now empty
    result_list_empty = cli_runner.invoke(review_app, ["list"])
    assert result_list_empty.exit_code == 0
    assert "No actions are pending review" in result_list_empty.stdout