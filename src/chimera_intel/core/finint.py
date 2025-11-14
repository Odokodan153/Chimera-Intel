"""
Module for Financial Intelligence (FININT).

Provides tools to analyze financial data, track insider trading, and assess
the financial health and risks of a company.
"""
import networkx as nx
from pyvis.network import Network
from typing_extensions import Annotated
from rich.panel import Panel
import typer
import logging
import json  
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from .schemas import (
    InsiderTradingResult,
    InsiderTransaction,
    TrademarkInfo,
    TrademarkSearchResult,
    CrowdfundingProject,         
    CrowdfundingAnalysisResult,  
    CrowdfundingCreator,
    FinancialTransaction,  
    MoneyFlowGraph,
    AmlSimulationResult,
    ScenarioImpact,      
)
from .utils import save_or_print_results
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .http_client import sync_client
from .project_manager import resolve_target
from .ai_core import analyze_transaction_patterns

logger = logging.getLogger(__name__)
console = Console()


def get_insider_transactions(stock_symbol: str) -> InsiderTradingResult:
    """
    Retrieves insider trading transactions for a given stock symbol using the Finnhub API.
    """
    api_key = API_KEYS.finnhub_api_key
    if not api_key:
        return InsiderTradingResult(
            stock_symbol=stock_symbol,
            error="Finnhub API key not found in .env file.",
        )
    logger.info(f"Fetching insider trading data for symbol: {stock_symbol}")

    base_url = "https://finnhub.io/api/v1/stock/insider-transactions"
    params = {"symbol": stock_symbol, "token": api_key}

    try:
        response = sync_client.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()

        transactions = [
            InsiderTransaction.model_validate(t) for t in data.get("data", [])
        ]
        return InsiderTradingResult(
            stock_symbol=stock_symbol, transactions=transactions
        )
    except Exception as e:
        logger.error(f"Failed to get insider transactions for {stock_symbol}: {e}")
        return InsiderTradingResult(
            stock_symbol=stock_symbol, error=f"An API error occurred: {e}"
        )


def search_trademarks(
    keyword: str, owner: Optional[str] = None
) -> TrademarkSearchResult:
    """
    Searches the USPTO database for pre-market signals using the MarkerAPI.
    """
    api_user = API_KEYS.uspto_api_username
    api_pass = API_KEYS.uspto_api_key  # Using the key field as the password

    if not api_user or not api_pass:
        return TrademarkSearchResult(
            keyword=keyword,
            error="USPTO_API_USERNAME or USPTO_API_KEY not found in .env file for MarkerAPI.",
        )

    trademarks = []
    base_url = "https://markerapi.com/api/v2/trademarks"
    params = {"start": 0, "username": api_user, "password": api_pass}

    try:
        if owner:
            logger.info(f"Searching for trademarks by owner: '{owner}'")
            # MarkerAPI V2 Owner Search:
            # /api/v2/trademarks/owner/{owner}/{status:all|active}/{start:int}/username/{username}/password/{password}
            url = f"{base_url}/owner/{owner}/all/{params['start']}/username/{params['username']}/password/{params['password']}"
            response = sync_client.get(url)
        else:
            logger.info(f"Searching for trademarks matching keyword: '{keyword}'")
            # MarkerAPI V2 Trademark Search:
            # /api/v2/trademarks/trademark/{trademark}/{status:all|active}/{start:int}/username/{username}/password/{password}
            url = f"{base_url}/trademark/{keyword}/all/{params['start']}/username/{params['username']}/password/{params['password']}"
            response = sync_client.get(url)

        response.raise_for_status()
        data = response.json()

        # The API returns a list of dictionaries directly
        if isinstance(data, list):
            for item in data:
                # Adapt the MarkerAPI response to our TrademarkInfo schema
                tm_info = {
                    "serialNumber": item.get("serial_number"),
                    "markText": item.get("trademark"),
                    "filingDate": item.get("filing_date"),
                    "status": item.get("status"),
                    "ownerName": item.get("owner"),
                    "description": item.get("description"),
                }
                trademarks.append(TrademarkInfo.model_validate(tm_info))

        elif data.get("error"):
            raise Exception(data.get("error"))

        return TrademarkSearchResult(
            keyword=keyword, owner=owner, trademarks=trademarks
        )

    except Exception as e:
        logger.error(
            f"Failed to search trademarks for {keyword} (Owner: {owner}): {e}"
        )
        return TrademarkSearchResult(
            keyword=keyword, owner=owner, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---


finint_app = typer.Typer(name="finint", help="Financial Intelligence (FININT) tools.")


@finint_app.command("track-insiders")
def run_insider_tracking(
    stock_symbol: Optional[str] = typer.Option(
        None, "--stock-symbol", "-s", help="The company stock symbol (e.g., AAPL)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Tracks insider trading activity for a given company stock symbol.
    """
    target_symbol = resolve_target(stock_symbol, required_assets=["stock_symbol"])
    console.print(
        f"Tracking insider trading for stock symbol: [bold cyan]{target_symbol}[/bold cyan]"
    )

    results_model = get_insider_transactions(target_symbol)
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    if not results_model.transactions:
        console.print("[yellow]No insider trading data found for this symbol.[/yellow]")
        return
    # Display results in a table

    table = Table(
        title=f"Insider Trading Activity for {results_model.stock_symbol}",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Insider Name", style="dim")
    table.add_column("Shares")
    table.add_column("Change")
    table.add_column("Transaction Date")
    table.add_column("Price")
    table.add_column("Code")

    for trans in results_model.transactions:
        table.add_row(
            trans.insiderName,
            str(trans.transactionShares),
            str(trans.change),
            str(trans.transactionDate),
            f"{trans.price:.2f}",
            trans.transactionCode,
        )
    console.print(table)

    # Save results if requested

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file:
        save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_symbol, module="finint_insider_tracking", data=results_dict
    )

def analyze_crowdfunding(keyword: str) -> CrowdfundingAnalysisResult:
    """
    Analyzes crowdfunding platforms (e.g., Kickstarter) for a given keyword
    using a real third-party API (RapidAPI).
    """
    api_key = API_KEYS.kickstarter_api_key
    if not api_key:
        logger.error("No KICKSTARTER_API_KEY found in .env file.")
        return CrowdfundingAnalysisResult(
            keyword=keyword,
            error="Kickstarter API key (KICKSTARTER_API_KEY) not found."
        )

    base_url = "https://kickstarter-data-api.p.rapidapi.com/search"
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "kickstarter-data-api.p.rapidapi.com"
    }
    params = {"query": keyword}
    
    logger.info(f"Fetching crowdfunding data for keyword: '{keyword}'")

    try:
        response = sync_client.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        projects_data = data.get("projects", [])
        parsed_projects: List[CrowdfundingProject] = []

        for item in projects_data:
            try:
                # Manually handle nested creator object
                creator_obj = CrowdfundingCreator.model_validate(item.get("creator", {}))
                
                # Create the main project object
                project = CrowdfundingProject.model_validate(item)
                project.creator = creator_obj.name # Flatten creator name
                
                parsed_projects.append(project)
            except Exception as e:
                logger.warning(f"Failed to parse project item: {item}. Error: {e}")
                continue # Skip this project if parsing fails

        return CrowdfundingAnalysisResult(keyword=keyword, projects=parsed_projects)

    except Exception as e:
        logger.error(f"Failed to get crowdfunding data for {keyword}: {e}", exc_info=True)
        return CrowdfundingAnalysisResult(
            keyword=keyword, error=f"An API error occurred: {e}"
        )


@finint_app.command("search-trademarks")
def run_trademark_search(
    keyword: Optional[str] = typer.Option(
        None, "--keyword", "-k", help="Keyword, product name, or logo to search."
    ),
    owner: Optional[str] = typer.Option(
        None, "--owner", "-o", help="The name of the company that owns the trademark."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", help="Save results to a JSON file."
    ),
):
    """
    Scans patent/trademark databases for pre-market signals.
    """
    if not keyword and not owner:
        console.print("[bold red]Error:[/bold red] Must provide either a --keyword or an --owner.")
        raise typer.Exit(code=1)

    target_owner = resolve_target(
        owner, required_assets=["company_name"], allow_none=True
    )
    search_term = keyword or "any"
    
    console.print(
        f"Searching for trademarks (Keyword: [cyan]'{keyword}'[/cyan], Owner: [cyan]'{target_owner}'[/cyan])..."
    )

    results_model = search_trademarks(search_term, owner=target_owner)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    if not results_model.trademarks:
        console.print("[yellow]No matching trademark applications found.[/yellow]")
        return

    # Display results in a table
    table_title = (
        f"Trademark Applications for Owner '{target_owner}'"
        if target_owner
        else f"Trademark Applications Matching '{keyword}'"
    )
    table = Table(
        title=table_title,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Serial Number")
    table.add_column("Filing Date")
    table.add_column("Mark Text")
    table.add_column("Owner")
    table.add_column("Status")
    table.add_column("Description", style="dim")

    for tm in results_model.trademarks:
        table.add_row(
            tm.serialNumber,
            str(tm.filingDate),
            tm.markText,
            tm.ownerName,
            tm.status,
            tm.description,
        )
    console.print(table)

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file:
        save_or_print_results(results_dict, output_file)
    
    db_target = target_owner or keyword
    save_scan_to_db(target=db_target, module="finint_trademark_search", data=results_dict)

@finint_app.command("track-crowdfunding")
def run_crowdfunding_analysis(
    keyword: str = typer.Argument(..., help="Keyword or project name to search for."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Tracks emerging funding sources on crowdfunding platforms.
    """
    console.print(
        f"Tracking crowdfunding projects matching: [bold cyan]{keyword}[/bold cyan]"
    )

    with console.status("[bold green]Analyzing crowdfunding platforms...[/]"):
        results_model = analyze_crowdfunding(keyword)
    
    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    if not results_model.projects:
        console.print("[yellow]No matching crowdfunding projects found.[/yellow]")
        return

    table = Table(
        title=f"Crowdfunding Projects for '{keyword}'",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Platform")
    table.add_column("Project Name")
    table.add_column("Pledged")
    table.add_column("Backers")
    table.add_column("Status")
    table.add_column("Creator")

    for project in results_model.projects:
        table.add_row(
            project.platform,
            project.project_name,
            f"${project.pledged:,.2f}",
            str(project.backers),
            project.status,
            project.creator,
        )
    console.print(table)

    results_dict = results_model.model_dump(exclude_none=True)
    if output_file:
        save_or_print_results(results_dict, output_file)
    
    save_scan_to_db(
        target=keyword, module="finint_crowdfunding", data=results_dict
    )

# --- Advanced AML & Scenario Simulation Features ---

def _load_transactions_from_file(filepath: str) -> List[FinancialTransaction]:
    """ (REAL) Loads financial transactions from a JSON file. """
    logger.info(f"Loading transactions from {filepath}")
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Expecting a list of transaction objects
        if not isinstance(data, list):
            raise ValueError("Invalid JSON format. Expected a list of transactions.")
            
        transactions = [FinancialTransaction.model_validate(t) for t in data]
        return transactions
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Transactions file not found at {filepath}")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/bold red] Could not parse JSON from {filepath}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error loading transactions:[/bold red] {e}")
        raise typer.Exit(code=1)


def build_transaction_graph(
    transactions: List[FinancialTransaction],
) -> nx.DiGraph:
    """Builds a NetworkX graph from a list of transactions."""
    g = nx.DiGraph()
    for t in transactions:
        if g.has_edge(t.from_account, t.to_account):
            g[t.from_account][t.to_account]["amount"] += t.amount
            g[t.from_account][t.to_account]["transactions"] += 1
            g[t.from_account][t.to_account]["label"] = f"${g[t.from_account][t.to_account]['amount']:,.2f} ({g[t.from_account][t.to_account]['transactions']} txns)"
        else:
            g.add_edge(t.from_account, t.to_account, amount=t.amount, transactions=1, label=f"${t.amount:,.2f} (1 txn)")
    return g


@finint_app.command("visualize-flow")
def run_visualize_money_flow(
    target: str = typer.Argument(..., help="Target entity to analyze money flow for."),
    transactions_file: str = typer.Option(
        ..., "--transactions-file", "-f", help="Path to a JSON file containing a list of transactions."
    ),
    output_file: str = typer.Option(
        ..., "--output", "-o", help="Save the graph to an HTML file."
    ),
    highlight: Optional[List[str]] = typer.Option(
        None, "--highlight", "-h", help="List of suspicious nodes to highlight in red."
    ),
):
    """
    Analyzes financial transactions from a file and builds a money flow network graph.
    """
    console.print(f"Building money flow graph for [bold cyan]{target}[/bold cyan]...")
    
    # 1. Get transaction data (from file)
    transactions = _load_transactions_from_file(transactions_file)
    if not transactions:
        console.print("[yellow]No transactions found in file.[/yellow]")
        return

    # 2. Build the graph object
    net = Network(height="800px", width="100%", notebook=True, directed=True)
    
    nodes = set()
    highlight_nodes = highlight or []

    for t in transactions:
        nodes.add(t.from_account)
        nodes.add(t.to_account)
        
        net.add_edge(
            t.from_account,
            t.to_account,
            label=f"${t.amount:,.2f}",
            title=f"ID: {t.transaction_id}<br>Time: {t.timestamp}",
            value=t.amount, # for scaling edge width
        )

    for node_id in nodes:
        color = "#FF6347" if node_id in highlight_nodes else "#4682B4" # Red or Blue
        size = 25 if node_id in highlight_nodes else 15
        net.add_node(node_id, label=node_id, color=color, size=size, title=node_id)

    # 3. Save graph
    try:
        net.show(output_file)
        console.print(f"[bold green]Successfully built graph.[/bold green]")
        console.print(f"[cyan]Money flow visualization saved to {output_file}[/cyan]")
        
        result = MoneyFlowGraph(
            graph_file=output_file,
            total_nodes=len(net.nodes),
            total_edges=len(net.edges),
            suspicious_nodes=highlight_nodes,
        ).model_dump()
        
        save_scan_to_db(
            target=target, module="finint_money_flow", data=result
        )
    except Exception as e:
        console.print(f"[bold red]Error saving graph:[/bold red] {e}")
        raise typer.Exit(code=1)


@finint_app.command("detect-patterns")
def run_aml_pattern_detection(
    target: str = typer.Argument(..., help="Target entity to scan for AML patterns."),
    transactions_file: str = typer.Option(
        ..., "--transactions-file", "-f", help="Path to a JSON file containing a list of transactions."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Uses AI to detect emerging money laundering techniques from a transaction file.
    """
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not found.")
        raise typer.Exit(code=1)

    console.print(f"Running AI pattern detection for [bold cyan]{target}[/bold cyan]...")
    
    # 1. Get transaction data
    transactions = _load_transactions_from_file(transactions_file)
    if not transactions:
        console.print("[yellow]No transactions found in file.[/yellow]")
        return

    # 2. Call AI Core function
    with console.status("[bold green]AI is analyzing transaction patterns...[/]"):
        results_model = analyze_transaction_patterns(target, transactions, api_key)

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    
    if not results_model.patterns_detected:
        console.print(f"[green]AI analysis complete:[/green] {results_model.summary}")
        return

    console.print(f"[bold green]AI Analysis Complete. {results_model.summary}[/bold green]")
    
    # 3. Display results in a table
    table = Table(
        title=f"Suspicious Patterns Detected for {target}",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Pattern Type", style="cyan")
    table.add_column("Confidence")
    table.add_column("Involved Accounts")
    table.add_column("Description")

    for pattern in results_model.patterns_detected:
        table.add_row(
            pattern.pattern_type,
            f"{pattern.confidence_score:.0%}",
            ", ".join(pattern.involved_accounts),
            pattern.description,
        )
    console.print(table)
    
    results_dict = results_model.model_dump(exclude_none=True)
    if output_file:
        save_or_print_results(results_dict, output_file)
    
    save_scan_to_db(
        target=target, module="finint_aml_patterns", data=results_dict
    )


@finint_app.command("simulate-scenario")
def run_scenario_simulation(
    target_node: Annotated[
        str,
        typer.Option(
            ...,
            "--node",
            "-n",
            help="The financial node (account) to affect.",
        ),
    ],
    scenario: Annotated[
        str,
        typer.Option(
            "sanction", # Default scenario
            "--scenario",
            "-s",
            help="The scenario to run (e.g., 'sanction', 'seizure').",
        ),
    ],
    transactions_file: str = typer.Option(
        ..., "--transactions-file", "-f", help="Path to a JSON file containing a list of transactions."
    ),
    target_entity: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="The overall target entity (for data retrieval). Uses node if not set.",
    ),
):
    """
    Tests "what-if" scenarios (e.g., sanctions) on a transaction network.
    """
    target = target_entity or target_node
    console.print(
        f"Simulating scenario '[bold yellow]{scenario}[/bold yellow]' on node '[bold red]{target_node}[/bold red]'..."
    )

    # 1. Get transactions and build graph
    transactions = _load_transactions_from_file(transactions_file)
    if not transactions:
        console.print("[yellow]No transactions found to build network.[/yellow]")
        return
        
    g = build_transaction_graph(transactions)

    if target_node not in g:
        console.print(f"[bold red]Error:[/bold red] Node '{target_node}' not found in the transaction graph.")
        raise typer.Exit(code=1)

    # 2. Run simulation
    # This is a "downstream" simulation: what nodes are fed by the target_node?
    try:
        # nx.descendants finds all nodes reachable from target_node
        downstream_nodes = list(nx.descendants(g, target_node))
        total_value_frozen = 0
        
        # Find all paths from the sanctioned node and sum the value
        for node in downstream_nodes:
            if g.has_edge(target_node, node):
                 total_value_frozen += g[target_node][node]["amount"]
            
        if not downstream_nodes:
            console.print(
                f"[green]Scenario complete.[/green] Node '{target_node}' is a terminal node. No downstream impact."
            )
            return

        impact = ScenarioImpact(
            node_affected=target_node,
            impact_type=scenario,
            affected_downstream_nodes=downstream_nodes,
            total_value_frozen=total_value_frozen # This is a simplified calculation
        )
        
        result_model = AmlSimulationResult(
            scenario_description=f"'{scenario}' applied to '{target_node}'",
            impacts=[impact]
        )

        # 3. Display results
        panel_content = (
            f"Affected Downstream Nodes: [bold cyan]{', '.join(downstream_nodes)}[/bold cyan]\n"
            f"Total Direct Outflow Value Frozen: [bold red]${total_value_frozen:,.2f}[/bold red]"
        )
        console.print(
            Panel(
                panel_content,
                title=f"[bold green]Simulation Impact Report[/bold green]",
                border_style="green",
            )
        )
        
        save_scan_to_db(
            target=target, module="finint_aml_simulation", data=result_model.model_dump()
        )

    except Exception as e:
        console.print(f"[bold red]An error occurred during simulation:[/bold red] {e}")
        raise typer.Exit(code=1)