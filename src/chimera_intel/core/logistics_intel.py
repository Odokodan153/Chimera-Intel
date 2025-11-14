"""
Logistics Intelligence Module for Chimera Intel.
Provides shipment tracking, vessel position tracking, trade manifest retrieval
and supply chain anomaly analysis.
"""
import logging
import asyncio
import httpx
import typer
from rich.console import Console
from rich.table import Table
from typing import List, Optional
from .schemas import (
    ShipmentDetails, 
    TrackingUpdate,
    VesselPosition,
    TradeManifest,
    TradeManifestResult,
    SupplyChainAnomaly,
    SupplyChainAnalysisResult
)
from .config_loader import API_KEYS
from .utils import save_or_print_results, console
from .project_manager import resolve_target
try:
    from .mlint import get_jurisdiction_risk, correlate_trade_payment
except ImportError:
    get_jurisdiction_risk = None
    correlate_trade_payment = None

logger = logging.getLogger(__name__)


# --- Existing Real Function ---

async def track_shipment(tracking_code: str, carrier: str) -> ShipmentDetails:
    """
    Tracks a shipment using the EasyPost API.
    """
    api_key = API_KEYS.easypost_api_key
    if not api_key:
        return ShipmentDetails(
            tracking_code=tracking_code,
            carrier=carrier,
            status="Error",
            error="EasyPost API key is not configured.",
        )
    url = "https://api.easypost.com/v2/trackers"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "tracker": {
            "tracking_code": tracking_code,
            "carrier": carrier,
        }
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            updates = [
                TrackingUpdate(
                    status=update.get("status"),
                    message=update.get("message"),
                    timestamp=update.get("datetime"),
                )
                for update in data.get("tracking_details", [])
            ]

            return ShipmentDetails(
                tracking_code=data.get("tracking_code"),
                carrier=data.get("carrier"),
                status=data.get("status"),
                estimated_delivery_date=data.get("est_delivery_date"),
                updates=updates,
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Error tracking shipment {tracking_code}: {e}")
            return ShipmentDetails(
                tracking_code=tracking_code,
                carrier=carrier,
                status="Error",
                error=f"API error: {e.response.text}",
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return ShipmentDetails(
                tracking_code=tracking_code,
                carrier=carrier,
                status="Error",
                error=str(e),
            )

# --- New REAL PHYSINT Function (Free API) ---

async def get_vessel_position_by_imo(imo: str) -> VesselPosition:
    """
    Gets live AIS position for a vessel from the free AISHUB API.
    
    NOTE: This is a real implementation. It requires a free API key
    from aishub.net (set as AISHUB_API_KEY in .env).
    This free API does *not* provide historical port calls.
    """
    api_key = API_KEYS.aishub_api_key
    if not api_key:
        return VesselPosition(error="AISHUB_API_KEY not configured.")

    url = "http://data.aishub.net/ws.php"
    params = {
        "username": api_key,
        "output": "json",
        "imo": imo,
        "compress": 0
    }
    headers = {"Accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            # AISHUB has a unique response format:
            # [ {ERROR: 0}, {DATA} ] or [ {ERROR: 1, ...} ]
            if not isinstance(data, list) or len(data) == 0:
                raise Exception(f"Unexpected API response format: {data}")
            
            status = data[0]
            if status.get("ERROR") != 0:
                return VesselPosition(error=f"AISHUB API Error: {status.get('ERROR_MSG', 'Unknown error')}")
            
            if len(data) < 2:
                return VesselPosition(error=f"No position data found for IMO {imo}.")

            vessel_data = data[1]
            vessel_data["imo"] = int(vessel_data["IMO"]) # Ensure IMO is int for validation
            
            return VesselPosition.model_validate(vessel_data)

    except httpx.HTTPStatusError as e:
        logger.error(f"Error tracking vessel {imo}: {e}")
        return VesselPosition(error=f"API error: {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return VesselPosition(error=str(e))

# --- New PHYSINT Function (Placeholder Template) ---

async def get_trade_manifests_by_company(company_name: str) -> TradeManifestResult:
    """
    [TEMPLATE] Searches a proprietary trade data provider (e.g., Panjiva,
    ImportGenius) for shipping manifests.
    
    NOTE: This is a *TEMPLATE* and requires a paid subscription to a
    proprietary trade data API. The endpoint and parsing logic must be
    adapted to your specific provider.
    
    It assumes the provider's endpoint is set in MLINT_TRADE_API_URL.
    """
    api_key = API_KEYS.trade_api_key
    base_url = API_KEYS.mlint_trade_api_url

    if not api_key:
        return TradeManifestResult(company_name=company_name, error="TRADE_API_KEY not configured.")
    if not base_url:
        return TradeManifestResult(company_name=company_name, error="MLINT_TRADE_API_URL (as trade data endpoint) not configured.")

    # --- DEVELOPER: MODIFY THIS SECTION ---
    # This endpoint is hypothetical. Replace with your provider's.
    url = f"{base_url.rstrip('/')}/v1/manifests/search"
    params = {"consignee_name": company_name, "limit": 50}
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    # --- END MODIFY ---

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # --- DEVELOPER: MODIFY THIS SECTION ---
            # This parsing logic is a template. Adapt it to your provider's
            # JSON response structure.
            manifests_data = data.get("manifests", [])
            manifests = []
            for m in manifests_data:
                try:
                    # Assumes the API response keys match our TradeManifest schema
                    manifests.append(TradeManifest.model_validate(m))
                except Exception as e:
                    logger.warning(f"Skipping malformed manifest record: {e}")
            # --- END MODIFY ---
            
            return TradeManifestResult(
                company_name=company_name,
                manifests=manifests,
                total_manifests=len(manifests)
            )
    except httpx.HTTPStatusError as e:
        logger.error(f"Error finding manifests for {company_name}: {e}")
        return TradeManifestResult(company_name=company_name, error=f"API error: {e.response.text}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return TradeManifestResult(company_name=company_name, error=str(e))

# --- New PHYSINT Function (Real Logic) ---

def analyze_supply_chain_anomalies(
    manifests: List[TradeManifest]
) -> SupplyChainAnalysisResult:
    """
    Analyzes manifests to find anomalies.
    
    NOTE: This analysis is limited to data present on the manifest
    (e.g., high-risk ports). It cannot detect suspicious routing
    without a paid AIS API that provides historical port calls.
    """
    if get_jurisdiction_risk is None:
        logger.error("MLINT's get_jurisdiction_risk function is not available.")
        return SupplyChainAnalysisResult(
            target_company="Multiple",
            analysis_summary="Analysis failed: MLINT module not loaded correctly.",
            total_anomalies=0,
            error="MLINT module dependency not loaded."
        )

    anomalies: List[SupplyChainAnomaly] = []
    
    for manifest in manifests:
        # 1. Check for high-risk ports
        ports_to_check = [manifest.port_of_lading, manifest.port_of_discharge]
        for port_str in ports_to_check:
            if not port_str:
                continue
            # Extract country code or name (e.g., "Shanghai, CHN" -> "CHN")
            country_name = port_str.split(",")[-1].strip()
            if not country_name:
                continue
                
            risk = get_jurisdiction_risk(country_name)
            if risk.risk_score >= 60: # FATF Grey List or higher
                anomalies.append(SupplyChainAnomaly(
                    anomaly_type="High-Risk Port",
                    description=f"Cargo transited through high-risk jurisdiction: {port_str} (Risk: {risk.risk_level})",
                    severity="Medium",
                    related_bill_of_lading=manifest.bill_of_lading_id,
                    related_vessel_imo=manifest.vessel_imo
                ))

        # 2. Suspicious Routing check (REMOVED)
        # This check is not possible with the free AIS API as it
        # does not provide historical port call data. A paid API
        # (and the old placeholder function) would be needed to
        # re-enable this feature.

    summary = f"Analysis complete. Found {len(anomalies)} anomalies across {len(manifests)} manifests."
    return SupplyChainAnalysisResult(
        target_company="Multiple", # This function is generic
        analysis_summary=summary,
        anomalies_found=anomalies,
        total_anomalies=len(anomalies)
    )

# --- Typer App & CLI Commands ---

app = typer.Typer(
    name="logistics",
    help="Provides logistics and shipment tracking intelligence.",
    no_args_is_help=True,
)


@app.command("track")
def run_shipment_tracking_cli(
    tracking_code: str = typer.Argument(..., help="The shipment's tracking code."),
    carrier: str = typer.Option(
        ..., "--carrier", "-c", help="The carrier (e.g., USPS, FedEx)."
    ),
):
    """
    Tracks a shipment (e.g., FedEx, USPS) and displays its current status.
    """
    console = Console()

    async def track():
        return await track_shipment(tracking_code, carrier)

    with console.status("[bold green]Tracking shipment...[/]"):
        result = asyncio.run(track())

    if result.error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)

    console.print(
        f"[bold]Status for {result.tracking_code} ({result.carrier}):[/] {result.status}"
    )
    if result.estimated_delivery_date:
        console.print(
            f"[bold]Estimated Delivery:[/bold] {result.estimated_delivery_date}"
        )
    table = Table(title="Tracking History")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Details", style="green")

    for update in result.updates:
        table.add_row(update.timestamp, update.status, update.message)
    console.print(table)

# --- New PHYSINT CLI Commands ---

@app.command("get-vessel-position")
def run_vessel_position_cli(
    imo: str = typer.Argument(..., help="The vessel's IMO number."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Gets the current live position of a vessel by IMO (free AIS data).
    """
    async def track():
        return await get_vessel_position_by_imo(imo)

    with console.status("[bold green]Tracking vessel via live AIS...[/]"):
        result = asyncio.run(track())

    if result.error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)

    if output_file:
        save_or_print_results(result.model_dump(exclude_none=True), output_file)

    console.print(
        f"[bold]Live Position for: {result.name} (IMO: {result.imo})[/]"
    )
    
    table = Table(title="Vessel Position Report")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Timestamp", result.timestamp)
    table.add_row("Latitude", str(result.latitude))
    table.add_row("Longitude", str(result.longitude))
    table.add_row("Speed (Knots)", str(result.speed))
    table.add_row("Course (Degrees)", str(result.course))
    
    console.print(table)


@app.command("find-manifests")
def run_trade_manifest_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target company name. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    [TEMPLATE] Finds shipping manifests (Bills of Lading) for a target.
    
    Requires a paid subscription to a trade data provider (e.g., Panjiva).
    """
    target_name = resolve_target(target, required_assets=["company_name"])
    
    async def find():
        return await get_trade_manifests_by_company(target_name)

    with console.status(f"[bold green]Searching trade databases for {target_name}...[/]"):
        result = asyncio.run(find())

    if result.error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)

    if output_file:
        save_or_print_results(result.model_dump(exclude_none=True), output_file)

    console.print(f"[bold]Found {result.total_manifests} manifests for {target_name}[/]")
    
    table = Table(title="Shipping Manifests")
    table.add_column("B/L ID", style="cyan")
    table.add_column("Date", style="magenta")
    table.add_column("Shipper", style="green")
    table.add_column("Consignee", style="green")
    table.add_column("Vessel IMO", style="yellow")
    table.add_column("Route", style="white")
    table.add_column("Cargo", style="blue")

    for m in result.manifests:
        route = f"{m.port_of_lading} -> {m.port_of_discharge}"
        table.add_row(
            m.bill_of_lading_id,
            m.ship_date,
            m.shipper_name,
            m.consignee_name,
            m.vessel_imo,
            route,
            m.cargo_description
        )
    console.print(table)


@app.command("analyze-supply-chain")
def run_supply_chain_analysis_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target company name. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes a target's supply chain for anomalies (PHYSINT).
    
    NOTE: Limited to manifest data (e.g., high-risk ports).
    """
    target_name = resolve_target(target, required_assets=["company_name"])
    
    async def analyze():
        # 1. Get all manifests for the company
        with console.status(f"[bold green]Fetching manifests for {target_name}...[/]"):
            manifest_result = await get_trade_manifests_by_company(target_name)
            if manifest_result.error:
                return SupplyChainAnalysisResult(target_company=target_name, error=manifest_result.error)
        
        manifests = manifest_result.manifests
        if not manifests:
            return SupplyChainAnalysisResult(target_company=target_name, analysis_summary="No manifests found for target.")

        # 2. Run the analysis (no vessel data available from free API)
        with console.status("[bold green]Analyzing for anomalies...[/]"):
            analysis_result = analyze_supply_chain_anomalies(manifests)
            analysis_result.target_company = target_name
        
        return analysis_result

    result = asyncio.run(analyze())

    if result.error:
        typer.echo(f"Error: {result.error}", err=True)
        raise typer.Exit(code=1)

    if output_file:
        save_or_print_results(result.model_dump(exclude_none=True), output_file)

    console.print(f"[bold]Supply Chain Analysis for {result.target_company}[/]")
    console.print(f"[bold]Summary:[/bold] {result.analysis_summary}")

    if result.anomalies_found:
        table = Table(title="Detected Anomalies")
        table.add_column("Severity", style="red")
        table.add_column("Type", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("B/L ID", style="yellow")
        
        for anomaly in result.anomalies_found:
            table.add_row(
                anomaly.severity,
                anomaly.anomaly_type,
                anomaly.description,
                anomaly.related_bill_of_lading
            )
        console.print(table)
    else:
        console.print("[green]No anomalies detected.[/green]")

@app.command("correlate-payment")
def run_mlint_correlation_cli(
    payment_id: str = typer.Option(..., "--payment-id", "-p", help="The unique ID of the payment (e.g., SWIFT ref)."),
    trade_doc_id: str = typer.Option(..., "--trade-doc-id", "-t", help="The unique ID of the trade doc (e.g., Bill of Lading)."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """
    [MLINT Integration] Correlate a payment with a trade document.
    """
    if correlate_trade_payment is None:
        console.print("[bold red]Error: MLINT module not loaded. Cannot correlate payment.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(f"Correlating Payment [cyan]{payment_id}[/cyan] with Trade Doc [cyan]{trade_doc_id}[/cyan]...")
    
    async def correlate():
        # This function is imported from .mlint
        return await correlate_trade_payment(payment_id, trade_doc_id)

    with console.status("[bold green]Running async trade/payment correlation...[/]"):
        results_model = asyncio.run(correlate())
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}"); raise typer.Exit(code=1)

    console.print(f"\n[bold magenta]Trade Correlation Report[/bold magenta]")
    if results_model.is_correlated:
        console.print(f"  [bold green]Result: Correlated[/bold green] (Confidence: {results_model.confidence})")
    else:
        console.print(f"  [bold red]Result: Not Correlated[/bold red] (Confidence: {results_model.confidence})")
        
    if results_model.mismatches:
        console.print("[bold]Mismatches Found:[/bold]")
        for mismatch in results_model.mismatches:
            console.print(f"  - [yellow]{mismatch}[/yellow]")
            
    if output_file: 
        save_or_print_results(results_model.model_dump(exclude_none=True), output_file)