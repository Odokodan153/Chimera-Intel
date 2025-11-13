import typer
import logging
import json
import boto3
import dnstwist
import CloudFlare
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional
from pathlib import Path

app = typer.Typer(
    help="Active Brand Protection: Deploy defensive assets and countermeasures."
)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ActiveBrandProtection:
    """
    Manages active defensive counter-intelligence operations using
    real-world libraries (Cloudflare, Boto3, dnstwist).
    """

    def __init__(self, cf_token: str = None, aws_key: str = None, aws_secret: str = None):
        self.cf = None
        if cf_token:
            try:
                self.cf = CloudFlare.CloudFlare(token=cf_token)
                # Test credentials by fetching zones
                self.cf.zones.get() 
                logger.info("Cloudflare client initialized and authenticated.")
            except Exception as e:
                logger.error(f"Cloudflare authentication failed: {e}")
                self.cf = None

        self.s3 = None
        if aws_key and aws_secret:
            try:
                self.s3 = boto3.client(
                    's3',
                    aws_access_key_id=aws_key,
                    aws_secret_access_key=aws_secret
                )
                # Test credentials
                self.s3.list_buckets()
                logger.info("Boto3 S3 client initialized and authenticated.")
            except ClientError as e:
                logger.error(f"Boto3 (AWS) authentication failed: {e}")
                self.s3 = None
        
        if not self.cf:
            logger.warning("Cloudflare client not available. Domain registration and sinkholing are disabled.")
        if not self.s3:
            logger.warning("Boto3 S3 client not available. Honeypot deployment is disabled.")

    def _get_cf_account_id(self) -> Optional[str]:
        """Helper to get the first available Cloudflare account ID."""
        try:
            accounts = self.cf.accounts.get()
            if not accounts:
                logger.error("No Cloudflare accounts found.")
                return None
            return accounts[0]['id']
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            logger.error(f"Error fetching Cloudflare account ID: {e}")
            return None

    def _generate_typos(self, domain: str) -> List[str]:
        """Generates typosquatting domains using dnstwist."""
        try:
            fuzz = dnstwist.DomainFuzz(domain)
            fuzz.generate()
            # Return only the 'domain' value from the fuzz results
            typos = [entry['domain'] for entry in fuzz.domains]
            logger.info(f"dnstwist generated {len(typos)} potential typos for {domain}")
            return typos
        except Exception as e:
            logger.error(f"Error during dnstwist generation: {e}")
            return []

    def register_typo_domains(self, primary_domain: str, dry_run: bool = True) -> Dict[str, str]:
        """Generates and registers common typo domains via Cloudflare."""
        if not self.cf:
            raise ConnectionError("Cloudflare client is not initialized. Cannot register domains.")
        
        account_id = self._get_cf_account_id()
        if not account_id:
            raise ConnectionError("Could not determine Cloudflare Account ID.")

        typos_to_check = self._generate_typos(primary_domain)
        results = {}

        for domain in typos_to_check:
            try:
                # 1. Check availability
                check_data = {'name': domain, 'account_id': account_id}
                # Using cf.accounts.registrar.domains.get() is the new way
                check_response = self.cf.accounts.registrar.domains.get(account_id, params={'name': domain})
                
                # Based on CF API, a non-empty list means it's registered
                if check_response:
                    results[domain] = "Already registered"
                    continue
                
                # If list is empty, it's available.
                if dry_run:
                    results[domain] = "Available (Dry Run)"
                    logger.info(f"[Dry Run] Domain {domain} is available for registration.")
                else:
                    # 2. Register if available and not dry_run
                    reg_data = {'name': domain}
                    reg_response = self.cf.accounts.registrar.domains.post(account_id, data=reg_data)
                    
                    if reg_response.get('name') == domain:
                        results[domain] = "Successfully registered"
                        logger.info(f"Successfully registered domain: {domain}")
                    else:
                        results[domain] = f"Registration failed: {reg_response}"
                        logger.warning(f"Failed to register {domain}: {reg_response}")

            except CloudFlare.exceptions.CloudFlareAPIError as e:
                # A 404 on domain check likely means it's available, but a 404 on post is an error.
                # This logic might need refinement based on exact API behavior.
                # For this example, we assume an API error means failure.
                logger.error(f"Cloudflare API error for {domain}: {e}")
                results[domain] = f"API error: {e}"
        
        return results

    def deploy_honeypot(self, file_path: Path, s3_bucket: str, s3_key: str, metadata: Dict[str, str]) -> Dict[str, Any]:
        """Deploys a honeypot (document, profile) to an S3 bucket."""
        if not self.s3:
            raise ConnectionError("Boto3 S3 client is not initialized. Cannot deploy honeypot.")
        
        if not file_path.exists():
            logger.error(f"Decoy file not found: {file_path}")
            return {"success": False, "error": "File not found"}

        try:
            # Add watermark_id or other tracking info to S3 object metadata
            extra_args = {'Metadata': metadata}
            
            self.s3.upload_file(
                str(file_path),
                s3_bucket,
                s3_key,
                ExtraArgs=extra_args
            )
            
            # Generate a presigned URL for access (optional) or just return the S3 URI
            s3_uri = f"s3://{s3_bucket}/{s3_key}"
            logger.info(f"Honeypot {file_path.name} deployed to {s3_uri} with metadata: {metadata}")
            return {"success": True, "url": s3_uri, "metadata": metadata}

        except ClientError as e:
            logger.error(f"Failed to deploy honeypot to S3: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return {"success": False, "error": str(e)}

    def sinkhole_domain(self, malicious_domain: str, sinkhole_ip: str) -> Dict[str, Any]:
        """Uses Cloudflare to sinkhole a malicious domain."""
        if not self.cf:
            raise ConnectionError("Cloudflare client is not initialized. Cannot sinkhole domain.")

        # 1. Find the Zone ID for the domain.
        # This assumes the *parent* domain (e.g., myproject.com) is in Cloudflare,
        # and we are creating a record for a *subdomain* (e.g., malicious-c2.myproject.com).
        # To sinkhole an arbitrary external domain, you'd need DNS provider integration.
        # We will assume we are controlling the TLD.
        
        parts = malicious_domain.split('.')
        if len(parts) < 2:
            logger.error("Invalid domain format. Cannot determine zone.")
            return {"success": False, "error": "Invalid domain format"}
        
        zone_name = '.'.join(parts[-2:])
        try:
            zones = self.cf.zones.get(params={'name': zone_name})
            if not zones:
                logger.error(f"Zone {zone_name} not found in this Cloudflare account.")
                return {"success": False, "error": f"Zone {zone_name} not found"}
            zone_id = zones[0]['id']
            
            # 2. Create/Update the DNS 'A' record
            dns_record = {
                'name': malicious_domain,
                'type': 'A',
                'content': sinkhole_ip,
                'ttl': 120, # Low TTL
                'proxied': False
            }
            
            # Check if record exists to update it (PUT), else create it (POST)
            existing_records = self.cf.zones.dns_records.get(zone_id, params={'name': malicious_domain, 'type': 'A'})
            
            if existing_records:
                record_id = existing_records[0]['id']
                self.cf.zones.dns_records.put(zone_id, record_id, data=dns_record)
                action = "updated"
            else:
                self.cf.zones.dns_records.post(zone_id, data=dns_record)
                action = "created"

            logger.info(f"Successfully {action} sinkhole record for {malicious_domain} to {sinkhole_ip}")
            return {"success": True, "domain": malicious_domain, "ip": sinkhole_ip}
            
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            logger.error(f"Failed to sinkhole {malicious_domain}: {e}")
            return {"success": False, "error": str(e)}

# --- Typer CLI Commands ---

# We cannot initialize the class here, as it needs API keys.
# We'll pass them in from the CLI commands.

@app.command()
def register_domains(
    primary_domain: str = typer.Option(..., help="The primary project domain to protect (e.g., myproject.com)"),
    cf_token: str = typer.Option(..., envvar="CLOUDFLARE_API_TOKEN", help="Cloudflare API Token."),
    live_run: bool = typer.Option(False, "--live-run", help="Actually register domains. Default is dry-run.")
):
    """
    Find and register common typos of your primary domain via Cloudflare.
    """
    if not cf_token:
        typer.secho("Error: CLOUDFLARE_API_TOKEN is required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    
    protector = ActiveBrandProtection(cf_token=cf_token)
    if not protector.cf:
        typer.secho("Cloudflare client initialization failed. Check token?", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if not live_run:
        typer.secho("Running in DRY-RUN mode. No domains will be registered.", fg=typer.colors.YELLOW)
    else:
        typer.secho("Running in LIVE mode. Domains will be registered.", fg=typer.colors.RED)

    results = protector.register_typo_domains(primary_domain, dry_run=not live_run)
    typer.echo(f"Domain Registration Results for {primary_domain}:")
    typer.echo(json.dumps(results, indent=2))

@app.command()
def deploy_decoy(
    file: Path = typer.Argument(..., help="Path to the decoy document."),
    s3_bucket: str = typer.Option(..., envvar="S3_BUCKET", help="Target S3 bucket."),
    s3_key: str = typer.Option(..., help="Path (key) for the object in S3 (e.g., 'decoys/doc.pdf')."),
    watermark: str = typer.Option(..., help="Unique ID to watermark the document with."),
    aws_key: str = typer.Option(None, envvar="AWS_ACCESS_KEY_ID", help="AWS Access Key."),
    aws_secret: str = typer.Option(None, envvar="AWS_SECRET_ACCESS_KEY", help="AWS Secret Key."),
):
    """
    Deploy a decoy honeypot document to an S3 bucket with metadata.
    """
    if not (aws_key and aws_secret):
        typer.secho("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    protector = ActiveBrandProtection(aws_key=aws_key, aws_secret=aws_secret)
    if not protector.s3:
        typer.secho("Boto3 S3 client initialization failed. Check AWS keys?", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Deploying {file.name} to s3://{s3_bucket}/{s3_key}...")
    metadata = {"watermark_id": watermark, "deploy_source": "active_brand_protection"}
    result = protector.deploy_honeypot(file, s3_bucket, s3_key, metadata)
    typer.echo(json.dumps(result, indent=2))

@app.command()
def sinkhole(
    domain: str = typer.Argument(..., help="The malicious domain to sinkhole (e.g., bad.myproject.com)."),
    sinkhole_ip: str = typer.Option("0.0.0.0", help="The IP to redirect traffic to (e.g., your honeywall)."),
    cf_token: str = typer.Option(..., envvar="CLOUDFLARE_API_TOKEN", help="Cloudflare API Token."),
):
    """
    Redirect a malicious domain (within your CF zone) to a sinkhole IP.
    """
    if not cf_token:
        typer.secho("Error: CLOUDFLARE_API_TOKEN is required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    protector = ActiveBrandProtection(cf_token=cf_token)
    if not protector.cf:
        typer.secho("Cloudflare client initialization failed. Check token?", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Attempting to sinkhole {domain} to {sinkhole_ip}...")
    result = protector.sinkhole_domain(domain, sinkhole_ip)
    typer.echo(json.dumps(result, indent=2))

if __name__ == "__main__":
    app()