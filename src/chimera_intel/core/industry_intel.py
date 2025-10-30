import logging
import asyncio
from typing import Optional
import typer
from .schemas import IndustryIntelResult, MonopolyAnalysisResult
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .business_intel import get_news_gnews
from .ai_core import generate_swot_from_data
from rich.markdown import Markdown

logger = logging.getLogger(__name__)


async def get_industry_analysis(
    industry: str, country: Optional[str] = None
) -> IndustryIntelResult:
    """
    Generates an AI-powered analysis of a specific industry, either globally or for a specific country.

    Args:
        industry (str): The industry to analyze (e.g., "water dispenser").
        country (str, optional): The country to focus the analysis on. Defaults to None for a global analysis.

    Returns:
        IndustryIntelResult: A Pydantic model with the AI-generated analysis.
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return IndustryIntelResult(
            industry=industry,
            country=country,
            analysis_text="",
            error="GNews and/or Google API key not found. Both are required for industry analysis.",
        )
    query = f'"{industry}" industry'
    if country:
        query += f" in {country}"
    logger.info(f"Gathering news for industry analysis with query: {query}")
    news_results = await get_news_gnews(query, gnews_key)

    if not news_results or not news_results.articles:
        return IndustryIntelResult(
            industry=industry,
            country=country,
            analysis_text="",
            error=f"Could not find any relevant news articles for the '{industry}' industry.",
        )
    # Combine the text from the top articles to feed to the AI

    articles_text = "\n".join(
        [
            f"Title: {article.title}\nDescription: {article.description}"
            for article in news_results.articles[:5]
        ]
    )

    location_scope = f"in {country}" if country else "globally"
    prompt = f"""
    As a market research analyst, provide a detailed analysis of the '{industry}' industry {location_scope}.
    Based *only* on the following news articles, generate a report in Markdown format covering these sections:

    1.  **Market Overview:** A brief summary of the current state of the industry.
    2.  **Key Trends & Innovations:** What are the major trends and new technologies shaping the market?
    3.  **Major Players:** Mention any companies that appear to be significant in these articles.
    4.  **Future Outlook:** Based on the articles, what is the likely future direction of this industry?

    **News Articles:**
    ---
    {articles_text}
    ---
    """

    with console.status("[bold cyan]AI is analyzing industry trends...[/bold cyan]"):
        ai_result = generate_swot_from_data(prompt, google_api_key)
    if ai_result.error:
        return IndustryIntelResult(
            industry=industry,
            country=country,
            analysis_text="",
            error=f"AI analysis failed: {ai_result.error}",
        )
    return IndustryIntelResult(
        industry=industry, country=country, analysis_text=ai_result.analysis_text
    )


async def check_monopoly_status(
    company_name: str, industry: str, country: Optional[str] = None
) -> MonopolyAnalysisResult:
    """
    Analyzes news and web data to determine if a company has a monopoly in a given industry.

    Args:
        company_name (str): The name of the company to analyze.
        industry (str): The industry to analyze.
        country (str, optional): The country to focus the analysis on. Defaults to None.

    Returns:
        MonopolyAnalysisResult: A Pydantic model with the AI-generated analysis.
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return MonopolyAnalysisResult(
            company_name=company_name,
            industry=industry,
            analysis_text="",
            error="GNews and/or Google API key not found. Both are required for this analysis.",
        )

    location_scope = f"in {country}" if country else "globally"
    query = f'"{company_name}" market share in "{industry}" industry {location_scope}'

    logger.info(f"Gathering data for monopoly analysis with query: {query}")
    news_results = await get_news_gnews(query, gnews_key)

    if not news_results or not news_results.articles:
        return MonopolyAnalysisResult(
            company_name=company_name,
            industry=industry,
            analysis_text="",
            error=f"Could not find any relevant news articles for the query: '{query}'.",
        )

    articles_text = "\n".join(
        [
            f"Title: {article.title}\nDescription: {article.description}"
            for article in news_results.articles[:5]
        ]
    )

    prompt = f"""
    As a senior market analyst specializing in antitrust and competition law, your task is to determine if '{company_name}'
    holds a monopoly in the '{industry}' industry {location_scope}.

    Based *only* on the provided news articles, generate a concise analysis in Markdown format. Address the following:

    1.  **Market Share Estimation:** Is there any mention of the company's market share percentage? If so, what is it?
    2.  **Competitive Landscape:** Are any major competitors mentioned? If so, who are they?
    3.  **Monopoly Assessment:** Based on the information, provide a conclusion on whether the company is likely to be a monopoly, a dominant player, or one of many competitors. Justify your answer.

    **News Articles:**
    ---
    {articles_text}
    ---
    """

    with console.status(
        "[bold cyan]AI is analyzing the competitive landscape...[/bold cyan]"
    ):
        ai_result = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return MonopolyAnalysisResult(
            company_name=company_name,
            industry=industry,
            analysis_text="",
            error=f"AI analysis failed: {ai_result.error}",
        )

    return MonopolyAnalysisResult(
        company_name=company_name,
        industry=industry,
        analysis_text=ai_result.analysis_text,
    )


industry_intel_app = typer.Typer()


@industry_intel_app.command("run")
def run_industry_analysis(
    industry: str = typer.Argument(
        ..., help="The industry to analyze (e.g., 'water dispenser')."
    ),
    country: Optional[str] = typer.Option(
        None, "--country", "-c", help="The country to focus on for the analysis."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Gathers and analyzes intelligence on a specific industry.
    """
    results_model = asyncio.run(get_industry_analysis(industry, country))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    console.print(
        f"\n--- [bold]Industry Analysis: {industry.title()}{f' in {country.title()}' if country else ' (Global)'}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{industry}_{country}" if country else industry
        save_scan_to_db(target=target_name, module="industry_intel", data=results_dict)


@industry_intel_app.command("monopoly")
def run_monopoly_check(
    company_name: str = typer.Argument(..., help="The name of the company to analyze."),
    industry: str = typer.Argument(..., help="The industry to analyze within."),
    country: Optional[str] = typer.Option(
        None, "--country", "-c", help="The country to focus the analysis on."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes if a company is a monopoly within a specific industry.
    """
    results_model = asyncio.run(check_monopoly_status(company_name, industry, country))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Monopoly Analysis: {company_name.title()} in {industry.title()}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{company_name}_{industry}_monopoly"
        save_scan_to_db(
            target=target_name, module="industry_intel_monopoly", data=results_dict
        )
