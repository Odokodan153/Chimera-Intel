# Tests/test_mlint_compliance.py

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

# Module under test
from src.chimera_intel.core.mlint_compliance import (
    PiiManager, 
    ReviewService, 
    ReviewCase
)
from src.chimera_intel.core.mlint_analysis import AMLAlert

# --- Test Fixtures ---

@pytest.fixture(name="sqlite_engine")
def sqlite_engine_fixture():
    """Create a fresh in-memory SQLite engine for each test."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    return engine

@pytest.fixture(name="session")
def session_fixture(sqlite_engine):
    """Yield a session from the in-memory SQLite engine."""
    with Session(sqlite_engine) as session:
        yield session

@pytest.fixture
def pii_manager():
    """A standard PiiManager."""
    return PiiManager(salt="test_salt")

@pytest.fixture
def review_service(session):
    """A ReviewService wired to the in-memory session."""
    return ReviewService(session)

@pytest.fixture
def sample_alert():
    """A sample AMLAlert with PII in the evidence."""
    return AMLAlert(
        type="STRAW_COMPANY",
        entity_id="c-12345",
        confidence=0.85,
        message="Company c-12345 (Shady Co) looks suspicious.",
        evidence={
            "entity_name": "Shady Co",
            "ubo_names": ["John Doe", "Jane Smith"],
            "address": "123 Main St",
            "entity_trail": [
                (['Wallet'], {'id': 'w-1', 'name': 'Johns Wallet'}),
                (['Company'], {'id': 'c-12345', 'name': 'Shady Co'})
            ]
        }
    )

# --- Test Cases ---

class TestPiiManager:
    def test_mask_pii_string(self, pii_manager):
        name = "John Doe"
        masked = pii_manager.mask_pii(name)
        
        assert masked.startswith("sha256:")
        assert len(masked) == 71 # "sha256:" + 64 hex chars
        assert masked != name
        
        # Test for idempotency
        assert pii_manager.mask_pii(name) == masked

    def test_mask_pii_different_strings(self, pii_manager):
        name1 = "John Doe"
        name2 = "Jane Doe"
        assert pii_manager.mask_pii(name1) != pii_manager.mask_pii(name2)

    def test_mask_aml_alert(self, pii_manager, sample_alert):
        masked_alert = pii_manager.mask_aml_alert(sample_alert)
        
        # Check original is unchanged
        assert sample_alert.evidence["entity_name"] == "Shady Co"
        
        # Check masked alert
        assert masked_alert.evidence["entity_name"] == pii_manager.mask_pii("Shady Co")
        assert "Shady Co" not in masked_alert.evidence["entity_name"]
        
        assert masked_alert.evidence["ubo_names"] == [
            pii_manager.mask_pii("John Doe"),
            pii_manager.mask_pii("Jane Smith")
        ]
        
        # Check entity trail masking
        trail = masked_alert.evidence["entity_trail"]
        assert trail[0][1]["name"] == pii_manager.mask_pii("Johns Wallet")
        assert trail[1][1]["name"] == pii_manager.mask_pii("Shady Co")


class TestReviewService:
    def test_submit_alert_for_review(self, review_service, session, sample_alert):
        # Action
        case = review_service.submit_alert_for_review(sample_alert)
        
        # Assertions
        assert case.id is not None
        assert case.status == "OPEN"
        assert case.alert_type == "STRAW_COMPANY"
        assert case.entity_id == "c-12345" # Original ID is stored for reference
        assert case.assignee is None
        
        # Check that the data *in the DB* is masked
        db_case = session.get(ReviewCase, case.id)
        assert db_case is not None
        
        alert_json = db_case.alert_json
        assert "Shady Co" not in alert_json
        assert "John Doe" not in alert_json
        assert review_service.pii_manager.mask_pii("Shady Co") in alert_json

    def test_get_cases_by_status(self, review_service, session, sample_alert):
        # Setup
        review_service.submit_alert_for_review(sample_alert)
        review_service.submit_alert_for_review(sample_alert)
        
        # Action
        open_cases = review_service.get_cases_by_status("OPEN")
        closed_cases = review_service.get_cases_by_status("ESCALATED")
        
        # Assertions
        assert len(open_cases) == 2
        assert len(closed_cases) == 0

    def test_resolve_case(self, review_service, session, sample_alert):
        # Setup
        case = review_service.submit_alert_for_review(sample_alert)
        assert case.status == "OPEN"
        
        # Action
        notes = "This is a confirmed high risk. Escalate to compliance."
        updated_case = review_service.resolve_case(
            case_id=case.id,
            new_status="ESCALATED",
            notes=notes,
            assignee="analyst1"
        )
        
        # Assertions
        assert updated_case is not None
        assert updated_case.id == case.id
        assert updated_case.status == "ESCALATED"
        assert updated_case.assignee == "analyst1"
        assert notes in updated_case.notes
        
        # Verify it's no longer "OPEN"
        open_cases = review_service.get_cases_by_status("OPEN")
        assert len(open_cases) == 0
        
        escalated_cases = review_service.get_cases_by_status("ESCALATED")
        assert len(escalated_cases) == 1

    def test_resolve_nonexistent_case(self, review_service):
        updated_case = review_service.resolve_case(
            case_id=999,
            new_status="ESCALATED",
            notes="N/A",
            assignee="analyst1"
        )
        assert updated_case is None

def test_alert_fusion_deduplicates_open_cases(self, review_service, session, sample_alert):
        # 1. Submit the first alert
        case1 = review_service.submit_alert_for_review(sample_alert)
        assert case1.id == 1
        assert case1.fusion_count == 1
        assert case1.notes is None
        
        # 2. Submit the *exact same* alert again
        case2 = review_service.submit_alert_for_review(sample_alert)
        
        # 3. Assert it returned the *same case*, but updated
        assert case2.id == case1.id
        assert case2.fusion_count == 2
        assert "Fused new 'STRAW_COMPANY' alert" in case2.notes
        assert "Total count: 2" in case2.notes

        # 4. Verify only one case exists in the database
        all_cases = session.exec(select(ReviewCase)).all()
        assert len(all_cases) == 1
        assert all_cases[0].id == 1
        assert all_cases[0].fusion_count == 2
        
    # --- NEW TEST ---
def test_fusion_does_not_affect_different_alerts(self, review_service, session, sample_alert):
        # 1. Submit the first alert
        review_service.submit_alert_for_review(sample_alert)
        
        # 2. Create a *different* alert (different entity)
        alert2 = sample_alert.copy(deep=True)
        alert2.entity_id = "c-67890"
        
        # 3. Submit the second alert
        case2 = review_service.submit_alert_for_review(alert2)
        assert case2.id == 2
        assert case2.fusion_count == 1

        # 4. Verify *two* cases exist
        all_cases = session.exec(select(ReviewCase)).all()
        assert len(all_cases) == 2
        
    # --- NEW TEST ---
def test_fusion_does_not_affect_resolved_cases(self, review_service, session, sample_alert):
        # 1. Submit the first alert
        case1 = review_service.submit_alert_for_review(sample_alert)
        
        # 2. Resolve it
        review_service.resolve_case(
            case_id=case1.id, 
            new_status="FALSE_POSITIVE", 
            notes="Not an issue.", 
            assignee="analyst1"
        )
        
        # 3. Submit the *same* alert again
        case2 = review_service.submit_alert_for_review(sample_alert)
        
        # 4. Assert a *new case* was created
        assert case2.id != case1.id
        assert case2.id == 2
        assert case2.status == "OPEN"
        assert case2.fusion_count == 1
        
        # 5. Verify two cases exist
        all_cases = session.exec(select(ReviewCase)).all()
        assert len(all_cases) == 2