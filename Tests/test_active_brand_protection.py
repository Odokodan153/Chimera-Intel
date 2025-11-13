import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from typer.testing import CliRunner
from botocore.exceptions import ClientError
from CloudFlare.exceptions import CloudFlareAPIError

# Import the module to test
from active_brand_protection import ActiveBrandProtection, app

runner = CliRunner()

# Mock external library imports
@pytest.fixture(autouse=True)
def mock_external_libs():
    """Mock entire libraries at the start of all tests."""
    with patch('active_brand_protection.boto3') as mock_boto, \
         patch('active_brand_protection.CloudFlare') as mock_cloudflare, \
         patch('active_brand_protection.dnstwist') as mock_dnstwist:
        
        # --- Mock Cloudflare ---
        mock_cf_client = MagicMock()
        mock_cf_client.zones.get.return_value = [{'id': 'ZONE_ID_123', 'name': 'example.com'}]
        mock_cf_client.accounts.get.return_value = [{'id': 'ACCOUNT_ID_123'}]
        mock_cloudflare.CloudFlare.return_value = mock_cf_client
        
        # --- Mock Boto3 ---
        mock_s3_client = MagicMock()
        mock_boto.client.return_value = mock_s3_client
        
        # --- Mock dnstwist ---
        mock_fuzz = MagicMock()
        mock_fuzz.domains = [
            {'domain': 'exmaple.com'},
            {'domain': 'example.co'}
        ]
        mock_dnstwist.DomainFuzz.return_value = mock_fuzz
        
        yield mock_boto, mock_cloudflare, mock_dnstwist

@pytest.fixture
def protector(mock_external_libs):
    """Fixture for an initialized ActiveBrandProtection class."""
    # Initialize with mock keys, the mock_external_libs fixture will catch them
    return ActiveBrandProtection(
        cf_token="mock_cf_token",
        aws_key="mock_aws_key",
        aws_secret="mock_aws_secret"
    )

def test_init_success(protector, mock_external_libs):
    mock_boto, mock_cloudflare, _ = mock_external_libs
    assert protector.cf is not None
    assert protector.s3 is not None
    mock_cloudflare.CloudFlare.assert_called_with(token="mock_cf_token")
    mock_boto.client.assert_called_with('s3', aws_access_key_id='mock_aws_key', aws_secret_access_key='mock_aws_secret')
    # Check that auth was tested
    protector.cf.zones.get.assert_called()
    protector.s3.list_buckets.assert_called()

def test_init_cf_fail(mock_external_libs):
    _, mock_cloudflare, _ = mock_external_libs
    # Simulate auth failure
    mock_cf_client = MagicMock()
    mock_cf_client.zones.get.side_effect = CloudFlareAPIError(1000, "Auth error")
    mock_cloudflare.CloudFlare.return_value = mock_cf_client
    
    protector = ActiveBrandProtection(cf_token="bad_token")
    assert protector.cf is None

def test_generate_typos(protector, mock_external_libs):
    _, _, mock_dnstwist = mock_external_libs
    typos = protector._generate_typos("example.com")
    mock_dnstwist.DomainFuzz.assert_called_with("example.com")
    assert "exmaple.com" in typos
    assert "example.co" in typos
    assert len(typos) == 2

def test_register_typo_domains_dry_run(protector):
    # Mock CF domain check to return empty (available)
    protector.cf.accounts.registrar.domains.get.return_value = []
    
    results = protector.register_typo_domains("example.com", dry_run=True)
    
    assert "exmaple.com" in results
    assert results["exmaple.com"] == "Available (Dry Run)"
    # POST (register) should NOT be called
    protector.cf.accounts.registrar.domains.post.assert_not_called()

def test_register_typo_domains_live_run(protector):
    # Mock CF domain check to return empty (available)
    protector.cf.accounts.registrar.domains.get.return_value = []
    # Mock successful registration
    protector.cf.accounts.registrar.domains.post.return_value = {'name': 'exmaple.com'}
    
    results = protector.register_typo_domains("example.com", dry_run=False)
    
    assert results["exmaple.com"] == "Successfully registered"
    protector.cf.accounts.registrar.domains.post.assert_called_with(
        'ACCOUNT_ID_123', data={'name': 'exmaple.com'}
    )

def test_register_typo_domains_already_registered(protector):
    # Mock CF domain check to return the domain (registered)
    protector.cf.accounts.registrar.domains.get.return_value = [{'name': 'exmaple.com'}]
    
    results = protector.register_typo_domains("example.com", dry_run=False)
    assert results["exmaple.com"] == "Already registered"

def test_deploy_honeypot_success(protector, tmp_path):
    decoy_file = tmp_path / "decoy.pdf"
    decoy_file.write_text("This is a decoy.")
    metadata = {"watermark_id": "track_123"}
    
    result = protector.deploy_honeypot(decoy_file, "my-bucket", "decoys/file.pdf", metadata)
    
    assert result["success"] is True
    assert result["url"] == "s3://my-bucket/decoys/file.pdf"
    protector.s3.upload_file.assert_called_with(
        str(decoy_file),
        "my-bucket",
        "decoys/file.pdf",
        ExtraArgs={'Metadata': metadata}
    )

def test_deploy_honeypot_s3_fail(protector, tmp_path):
    decoy_file = tmp_path / "decoy.pdf"
    decoy_file.write_text("This is a decoy.")
    protector.s3.upload_file.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "upload_file")
    
    result = protector.deploy_honeypot(decoy_file, "my-bucket", "file.pdf", {})
    assert result["success"] is False
    assert "AccessDenied" in result["error"]

def test_sinkhole_domain_create_new(protector):
    # Mock DNS record search to return empty (no existing record)
    protector.cf.zones.dns_records.get.return_value = []
    
    result = protector.sinkhole_domain("bad.example.com", "0.0.0.0")
    
    assert result["success"] is True
    # POST (create) should be called
    protector.cf.zones.dns_records.post.assert_called_once()
    # PUT (update) should NOT be called
    protector.cf.zones.dns_records.put.assert_not_called()

def test_sinkhole_domain_update_existing(protector):
    # Mock DNS record search to return an existing record
    existing_record = [{'id': 'DNS_RECORD_ID_456', 'name': 'bad.example.com'}]
    protector.cf.zones.dns_records.get.return_value = existing_record
    
    result = protector.sinkhole_domain("bad.example.com", "1.2.3.4")
    
    assert result["success"] is True
    # PUT (update) should be called
    protector.cf.zones.dns_records.put.assert_called_once()
    # POST (create) should NOT be called
    protector.cf.zones.dns_records.post.assert_not_called()

# --- CLI Tests ---
# We patch the class itself to avoid needing to mock the internal libs again

@patch('active_brand_protection.ActiveBrandProtection')
def test_cli_register_domains_dry_run(MockProtector):
    mock_instance = MagicMock()
    mock_instance.cf = True # Simulate successful init
    mock_instance.register_typo_domains.return_value = {"exmaple.com": "Available (Dry Run)"}
    MockProtector.return_value = mock_instance

    result = runner.invoke(app, [
        "register-domains",
        "--primary-domain", "example.com",
        "--cf-token", "test_token"
    ])
    
    assert result.exit_code == 0
    assert "Running in DRY-RUN mode" in result.stdout
    assert "exmaple.com" in result.stdout
    mock_instance.register_typo_domains.assert_called_with("example.com", dry_run=True)

@patch('active_brand_protection.ActiveBrandProtection')
def test_cli_deploy_decoy_success(MockProtector, tmp_path):
    mock_instance = MagicMock()
    mock_instance.s3 = True # Simulate successful init
    mock_instance.deploy_honeypot.return_value = {"success": True}
    MockProtector.return_value = mock_instance
    
    decoy_file = tmp_path / "decoy.txt"
    decoy_file.write_text("decoy")

    result = runner.invoke(app, [
        "deploy-decoy",
        str(decoy_file),
        "--s3-bucket", "my-bucket",
        "--s3-key", "my-key",
        "--watermark", "wm-123",
        "--aws-key", "key",
        "--aws-secret", "secret"
    ])
    
    assert result.exit_code == 0
    assert '"success": true' in result.stdout

@patch('active_brand_protection.ActiveBrandProtection')
def test_cli_sinkhole_success(MockProtector):
    mock_instance = MagicMock()
    mock_instance.cf = True # Simulate successful init
    mock_instance.sinkhole_domain.return_value = {"success": True}
    MockProtector.return_value = mock_instance
    
    result = runner.invoke(app, [
        "sinkhole",
        "bad.example.com",
        "--sinkhole-ip", "1.2.3.4",
        "--cf-token", "test_token"
    ])
    
    assert result.exit_code == 0
    assert '"success": true' in result.stdout
    mock_instance.sinkhole_domain.assert_called_with("bad.example.com", "1.2.3.4")

def test_cli_command_missing_token():
    result = runner.invoke(app, ["sinkhole", "bad.com"])
    assert result.exit_code == 1
    assert "Error: CLOUDFLARE_API_TOKEN is required" in result.stdout