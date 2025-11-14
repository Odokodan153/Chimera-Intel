"""
CLIMAINT (Climate Intelligence) Module for Chimera Intel.

Provides strategic-level analysis of climate-driven geopolitical and 
supply chain risks, expanding on tactical WEATHINT and ECOINT data.
"""

import typer
import httpx
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any
from rich.panel import Panel
from rich.syntax import Syntax
from .utils import console
from .schemas import AiCoreResult, ClimaintReport
from .gemini_client import GeminiClient
from .config_loader import API_KEYS

climaint_app = typer.Typer(
    name="climaint",
    help="Performs strategic Climate Intelligence (CLIMAINT) tasks.",
)

# --- Mappings ---

# Simplified mapping for example. A real implementation would use a library.
COUNTRY_ISO_CODES: Dict[str, str] = {
    "chile": "CL",
    "australia": "AU",
    "china": "CN",
    "usa": "US",
    "dr congo": "CD",
    "russia": "RU",
}

# Key "green tech" and resource commodity codes
COMMODITY_HS_CODES: Dict[str, str] = {
    "lithium": "283691",  # Lithium carbonates
    "cobalt": "810520",  # Cobalt mattes and other intermediate products
    "rare-earth": "280530",  # Rare-earth metals, scandium and yttrium
    "water": "2201",  # Waters, including natural or artificial mineral waters
    "copper": "7403",  # Refined copper and copper alloys
}

# World Bank indicators
# PV.PER.ALL.Z = Political Stability and Absence of Violence/Terrorism (Percentile Rank)
# AG.LND.EL5M.ZS = Land area where elevation is below 5 meters (% of total land area)
INDICATOR_MAP: Dict[str, str] = {
    "political_stability": "PV.PER.ALL.Z",
    "sea_level_risk_land": "AG.LND.EL5M.ZS",
}


class Climaint:
    """
    Handles CLIMAINT data gathering and strategic analysis.
    """

    def __init__(self):
        self.wb_base_url = "https://api.worldbank.org/v2"
        self.comtrade_base_url = "https://comtrade.un.org/api/get"
        self.comtrade_api_key = API_KEYS.comtrade_api_key
        if not self.comtrade_api_key:
            console.print(
                "[bold yellow]Warning:[/bold yellow] COMTRADE_API_KEY not set. Supply chain analysis will be limited.",
                style="yellow",
            )
        self.client = httpx.Client(timeout=20.0, follow_redirects=True)

    def _get_world_bank_indicator(
        self, country_code: str, indicator_code: str
    ) -> Dict[str, Any]:
        """
        Fetches the most recent value for a World Bank indicator.
        """
        url = f"{self.wb_base_url}/country/{country_code}/indicator/{indicator_code}"
        params = {"format": "json", "per_page": 1, "mrnev": "1"}  # Most Recent 1 Value
        try:
            response = self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            if not data or len(data) < 2 or not data[1]:
                return {"error": "No data found for indicator."}

            record = data[1][0]
            return {
                "indicator": record.get("indicator", {}).get("value"),
                "country": record.get("country", {}).get("value"),
                "year": record.get("date"),
                "value": record.get("value"),
            }
        except httpx.HTTPStatusError as e:
            return {"error": f"World Bank API error: {e.response.text}"}
        except Exception as e:
            return {"error": f"Unexpected error fetching WB data: {e}"}

    def _get_comtrade_data(
        self, commodity_code: str, country_code_iso: str
    ) -> Dict[str, Any]:
        """
        Fetches the last 12 months of trade data for a commodity and country.
        """
        if not self.comtrade_api_key:
            return {"error": "COMTRADE_API_KEY is not configured."}

        # Get last 12 months (e.g., "202410,202409,202408...")
        now = datetime.now()
        periods = [
            (now - timedelta(days=i * 30)).strftime("%Y%m") for i in range(12, 0, -1)
        ]

        # Note: UN Comtrade uses M49 codes. ISO to M49 mapping is needed.
        # For this example, we'll assume a direct mapping or simple lookup.
        # e.g., 'CL' (ISO) -> '152' (M49)
        # We will cheat for this example and just use the ISO code if it fails
        
        # A proper app would have this mapping.
        M49_MAP = {"CL": "152", "AU": "036", "CN": "156", "US": "842", "CD": "180", "RU": "643"}
        reporter_code = M49_MAP.get(country_code_iso, "all")

        params = {
            "r": reporter_code,  # Reporter country
            "p": "all",  # Partner country
            "ps": ",".join(periods),  # Time periods
            "cmd": commodity_code,  # Commodity code
            "token": self.comtrade_api_key,
            "fmt": "json",
            "rg": "1,2",  # Imports and Exports
        }

        try:
            response = self.client.get(self.comtrade_base_url, params=params)
            response.raise_for_status()
            data = response.json().get("dataset", [])
            if not data:
                return {"error": "No trade data found."}

            df = pd.DataFrame(data)
            df["TradeValue"] = pd.to_numeric(df["TradeValue"])
            
            # Summarize imports and exports
            summary = df.groupby("rgDesc")["TradeValue"].sum().to_dict()
            return {
                "total_records": len(df),
                "summary_usd": summary,
                "data_snippet": df.head(2).to_dict("records"),
            }

        except httpx.HTTPStatusError as e:
            return {"error": f"Comtrade API error: {e.response.text}"}
        except Exception as e:
            return {"error": f"Unexpected error fetching Comtrade data: {e}"}

    def _get_ai_analysis(
        self, country: str, resource: str, data: Dict[str, Any]
    ) -> AiCoreResult:
        """
        Uses the GeminiClient to generate a strategic analysis.
        """
        client = GeminiClient()
        if not client.is_configured():
            return AiCoreResult(
                error="AI Core (Gemini) is not configured. Please set GEMINI_API_KEY."
            )

        prompt = f"""
        Act as a senior geopolitical and supply chain risk analyst. I am providing you
        with raw data feeds for {country} related to its role in the {resource} supply chain.
        
        Your task is to synthesize these inputs into a concise, strategic report (approx. 3-5 paragraphs)
        for an executive audience.
        
        Focus on:
        1.  The overall stability and climate vulnerability of the country.
        2.  The country's significance in the global supply chain for this specific resource.
        3.  The primary long-term risks (geopolitical, climate-driven, trade) that could disrupt this supply chain.
        
        DATA FEEDS:
        
        1.  Political Stability (World Bank, Percentile Rank, higher is more stable):
            {data.get('political_stability')}
        
        2.  Climate Vulnerability (World Bank, % of land area below 5m elevation):
            {data.get('climate_risk_land')}
        
        3.  Resource Trade Flow (UN Comtrade, last 12 months for {resource}):
            {data.get('trade_data')}
        
        ---
        STRATEGIC CLIMAINT REPORT:
        """
        
        try:
            analysis_text = client.generate_text(prompt)
            return AiCoreResult(analysis_text=analysis_text)
        except Exception as e:
            return AiCoreResult(error=f"AI analysis failed: {e}")


@climaint_app.command("report")
def geopolitical_risk_report(
    country: str = typer.Argument(
        ..., help="The target country name (e.g., 'Chile', 'DR Congo')."
    ),
    resource: str = typer.Argument(
        ..., help="The target resource (e.g., 'Lithium', 'Cobalt')."
    ),
):
    """
    Generates a strategic report on climate-driven geopolitical and
    supply chain risks for a country and resource.
    """
    country_key = country.lower()
    resource_key = resource.lower()

    if country_key not in COUNTRY_ISO_CODES:
        console.print(
            f"[bold red]Error:[/bold red] Country '{country}' not in mapping. "
            f"Available: {list(COUNTRY_ISO_CODES.keys())}"
        )
        raise typer.Exit(code=1)
    if resource_key not in COMMODITY_HS_CODES:
        console.print(
            f"[bold red]Error:[/bold red] Resource '{resource}' not in mapping. "
            f"Available: {list(COMMODITY_HS_CODES.keys())}"
        )
        raise typer.Exit(code=1)

    country_iso = COUNTRY_ISO_CODES[country_key]
    hs_code = COMMODITY_HS_CODES[resource_key]
    engine = Climaint()
    all_data = {}

    console.print(
        f"[bold cyan]Generating CLIMAINT Report for {country.title()} ({resource.title()})...[/bold cyan]"
    )

    with console.status("[bold green]Fetching political stability data...[/bold green]"):
        all_data["political_stability"] = engine._get_world_bank_indicator(
            country_iso, INDICATOR_MAP["political_stability"]
        )

    with console.status("[bold green]Fetching climate vulnerability data...[/bold green]"):
        all_data["climate_risk_land"] = engine._get_world_bank_indicator(
            country_iso, INDICATOR_MAP["sea_level_risk_land"]
        )

    with console.status("[bold green]Fetching resource trade flow data...[/bold green]"):
        all_data["trade_data"] = engine._get_comtrade_data(hs_code, country_iso)

    with console.status("[bold blue]Synthesizing strategic analysis (AI Core)...[/bold blue]"):
        ai_result = engine._get_ai_analysis(country, resource, all_data)
        
    if ai_result.error:
        console.print(f"\n[bold red]AI Analysis Failed:[/bold red] {ai_result.error}")
        raise typer.Exit(code=1)

    # --- Construct the final report ---
    report = ClimaintReport(
        target_country=country,
        target_resource=resource,
        strategic_summary=ai_result.analysis_text,
        political_stability_data=all_data["political_stability"],
        climate_risk_data=all_data["climate_risk_land"],
        trade_flow_summary=all_data["trade_data"],
    )

    console.print(
        Panel(
            report.strategic_summary,
            title=f"[bold green]CLIMAINT Strategic Report: {country.title()} - {resource.title()}[/bold green]",
            border_style="green",
        )
    )

    console.print("\n[bold]--- Supporting Data ---[/bold]")
    console.print(Syntax(report.model_dump_json(indent=2), "json", theme="monokai"))


if __name__ == "__main__":
    climaint_app()