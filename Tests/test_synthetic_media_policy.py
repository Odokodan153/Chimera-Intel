import pytest

# Module under test
from chimera_intel.core import synthetic_media_policy as smp
from chimera_intel.core.synthetic_media_policy import GenerationRequest

# --- Test Cases ---

def test_policy_check_allowed_low_risk():
    """
    Tests allowed generation: stock face for internal marketing.
    (Req 9 - Allowed generation, single operator OK)
    """
    request = GenerationRequest(
        subject_name="stock_face_001",
        subject_category="stock_synthetic_face",
        use_case="internal_marketing",
        requesting_operator="op_test_user"
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is True
    assert result.is_blocked is False
    assert result.risk_level == "low"
    assert result.approval_required == "single_operator"
    assert result.retention_policy_applies is True

def test_policy_check_allowed_medium_risk_dual_approval():
    """
    Tests allowed generation: consenting adult for public marketing.
    (Req 9 - Allowed generation, dual approval required)
    """
    request = GenerationRequest(
        subject_name="Jane Doe (Actor)",
        subject_category="consenting_adult_corporate",
        use_case="public_facing_marketing",
        requesting_operator="op_test_user",
        consent_proof_id="consent_doc_778"
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is True
    assert result.is_blocked is False
    assert result.risk_level == "medium"
    assert result.approval_required == "dual_approval"
    assert result.retention_policy_applies is True

def test_policy_check_blocked_minor():
    """
    Tests blocked generation: a minor.
    (Req 9 - Blocked: minors)
    """
    request = GenerationRequest(
        subject_name="Child Actor",
        subject_category="minor", # This is in BLOCKED_SUBJECT_CATEGORIES
        use_case="internal_training",
        requesting_operator="op_test_user"
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is False
    assert result.is_blocked is True
    assert "BLOCKED: Generation of subject category 'minor'" in result.reason

def test_policy_check_blocked_sanctioned_person():
    """
    Tests blocked generation: a sanctioned person.
    (Req 9 - Blocked: sanctioned persons)
    """
    request = GenerationRequest(
        subject_name="Sanctioned Individual",
        subject_category="sanctioned_person", # This is in BLOCKED_SUBJECT_CATEGORIES
        use_case="deception_research",
        requesting_operator="op_test_user"
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is False
    assert result.is_blocked is True
    assert "BLOCKED: Generation of subject category 'sanctioned_person'" in result.reason

def test_policy_check_blocked_sensitive_no_consent():
    """
    Tests blocked generation: sensitive public official without consent.
    (Req 9 - Blocked: public officials in sensitive roles)
    """
    request = GenerationRequest(
        subject_name="Judge Example",
        subject_category="public_official_sensitive",
        use_case="internal_training",
        requesting_operator="op_test_user",
        consent_proof_id=None # Missing consent
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is False
    assert result.is_blocked is True
    assert "requires a valid consent_proof_id" in result.reason

def test_policy_check_blocked_adult_no_consent():
    """
    Tests blocked generation: consenting adult category but no consent ID provided.
    """
    request = GenerationRequest(
        subject_name="Jane Doe",
        subject_category="consenting_adult_corporate",
        use_case="internal_marketing",
        requesting_operator="op_test_user",
        consent_proof_id=None # Missing consent
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is False
    assert result.is_blocked is True
    assert "requires a 'consent_proof_id'" in result.reason

def test_policy_check_blocked_unknown_use_case():
    """
    Tests blocked generation: use case is not in the approved list.
    """
    request = GenerationRequest(
        subject_name="stock_face_002",
        subject_category="stock_synthetic_face",
        use_case="personal_deepfake_joke", # Not in USE_CASE_RISK_LEVELS
        requesting_operator="op_test_user"
    )
    
    result = smp.check_generation_policy(request)
    
    assert result.is_allowed is False
    assert result.is_blocked is True
    assert "BLOCKED: Unknown use_case" in result.reason

def test_get_retention_policy_text():
    """
    Tests the retention policy text retrieval.
    (Req 9 - Retention: min 7 years)
    """
    text = smp.get_retention_policy_text()
    assert "minimum of 7 years" in text
    assert str(smp.RETENTION_POLICY_YEARS) in text