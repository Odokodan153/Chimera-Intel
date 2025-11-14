"""
This module provides AI-powered business intelligence tools
for industry analysis, monopoly checks, stability forecasts,
patent/R&D tracking, market intelligence, and ESG monitoring.
Each async function gathers relevant news and data, generates
a structured analysis using AI, and returns a Pydantic result
model. CLI commands allow running these analyses and saving
results to JSON or a database.
"""
import logging
import asyncio
from typing import Optional, Dict, Any, List
import typer
from .schemas import (
    IndustryIntelResult,
    MonopolyAnalysisResult,
    StabilityForecastResult,
    PatentRDResult,  
    MarketIntelResult, 
    ESGMonitorResult,  
)
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .business_intel import get_news_gnews, GNewsArticle
from .ai_core import generate_swot_from_data, SWOTAnalysisResult
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


async def get_stability_forecast(
    country: str, region: Optional[str] = None
) -> StabilityForecastResult:
    """
    Generates a stability forecast by fusing multi-modal news data
    (political, economic, social) and historical data (via AI).
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return StabilityForecastResult(
            country=country,
            region=region,
            analysis_text="",
            short_term_index=0,
            long_term_index=0,
            key_factors={},
            error="GNews and/or Google API key not found.",
        )

    target_location = f"{country}, {region}" if region else country
    logger.info(f"Gathering multi-modal data for stability forecast in {target_location}")

    # Define multi-modal queries
    queries = {
        "political": f"political stability in {target_location} OR government approval {target_location} OR election",
        "economic": f"economic forecast {target_location} OR inflation {target_location} OR unemployment {target_location}",
        "social": f"civil unrest {target_location} OR protests in {target_location} OR social sentiment {target_location}",
        "ecoint": f"drought OR famine OR energy crisis in {target_location}",
        "legint": f"new laws {target_location} OR regulations {target_location} OR judicial reform {target_location}",
    }

    # Gather data concurrently
    with console.status("[bold cyan]Gathering multi-modal data...[/bold cyan]"):
        tasks = [get_news_gnews(q, gnews_key, max_results=3) for q in queries.values()]
        results = await asyncio.gather(*tasks)

    # Process and fuse data
    all_articles: Dict[str, List[GNewsArticle]] = {}
    fused_data_text = ""
    key_factors: Dict[str, Any] = {"sources_found": {}}

    for (factor, query), news_result in zip(queries.items(), results):
        if news_result and news_result.articles:
            key_factors["sources_found"][factor] = len(news_result.articles)
            all_articles[factor] = news_result.articles
            fused_data_text += f"--- Data for: {factor.upper()} ---\n"
            fused_data_text += "\n".join(
                [
                    f"Title: {article.title}\nDescription: {article.description}\nSource: {article.source.name}\n"
                    for article in news_result.articles
                ]
            )
            fused_data_text += "\n\n"
        else:
            key_factors["sources_found"][factor] = 0

    if not fused_data_text:
        return StabilityForecastResult(
            country=country,
            region=region,
            analysis_text="",
            short_term_index=0,
            long_term_index=0,
            key_factors=key_factors,
            error=f"Could not find any relevant data for {target_location}.",
        )

    # Define the advanced AI prompt
    prompt = f"""
    As a geopolitical risk analyst, generate a stability forecast for {target_location}.
    Based *only* on the following multi-modal data, provide a report in Markdown format.

    **Fused Data (Political, Economic, Social, ECOINT, LEGINT):**
    ---
    {fused_data_text}
    ---

    **Instructions:**
    1.  **Analyze Key Factors:** For each domain (Political, Economic, Social, etc.),
        identify the key risk factors and stabilizers mentioned in the data.
    2.  **Generate Stability Index:** Provide a "Short-Term Index" (3-6 months) and a
        "Long-Term Index" (1-3 years). Use a scale from -10 (High Instability/Collapse)
        to +10 (High Stability).
    3.  **Write Analysis & Forecast:** Synthesize your findings into a coherent analysis.
        Explain the reasoning for your stability indices.

    **Output Format:**
    
    ### Stability Forecast: {target_location}

    * **Short-Term Index (3-6 mo):** [Your value, e.g., -2.5]
    * **Long-Term Index (1-3 yr):** [Your value, e.g., -4.0]

    #### Key Risk Factors:
    * **Political:** [Identify 1-2 key political risks from data]
    * **Economic:** [Identify 1-2 key economic risks from data]
    * **Social/Ecoint/Legint:** [Identify 1-2 key risks from other data]

    #### Key Stabilizers:
    * [Identify 1-2 key stabilizing factors from data, if any]

    #### Analysis & Forecast:
    [Your detailed analysis here, explaining the indices and trajectory.]
    """

    with console.status("[bold cyan]AI is forecasting stability...[/bold cyan]"):
        ai_result: SWOTAnalysisResult = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return StabilityForecastResult(
            country=country,
            region=region,
            analysis_text="",
            short_term_index=0,
            long_term_index=0,
            key_factors=key_factors,
            error=f"AI analysis failed: {ai_result.error}",
        )

    # TODO: Parse the `analysis_text` to extract the indices
    # For now, we return 0 and the full text.
    return StabilityForecastResult(
        country=country,
        region=region,
        analysis_text=ai_result.analysis_text,
        short_term_index=0.0,  # Placeholder, needs parsing
        long_term_index=0.0,  # Placeholder, needs parsing
        key_factors=key_factors,
        error=None,
    )


# +++ NEW FUNCTION +++
async def track_patent_rd(
    topic: str, company: Optional[str] = None
) -> PatentRDResult:
    """
    Monitors new patents, publications, and research directions for a given topic or company.

    Args:
        topic (str): The industry, technology, or scientific field (e.g., "graphene").
        company (str, optional): A specific company to focus on. Defaults to None.

    Returns:
        PatentRDResult: A Pydantic model with the AI-generated analysis.
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return PatentRDResult(
            topic=topic,
            company=company,
            analysis_text="",
            error="GNews and/or Google API key not found. Both are required for this analysis.",
        )

    query = f'"{topic}" patent OR "{topic}" R&D OR "{topic}" research'
    if company:
        query += f' AND "{company}"'

    logger.info(f"Gathering data for R&D tracking with query: {query}")
    news_results = await get_news_gnews(query, gnews_key)

    if not news_results or not news_results.articles:
        return PatentRDResult(
            topic=topic,
            company=company,
            analysis_text="",
            error=f"Could not find any relevant news articles for the query: '{query}'.",
        )

    articles_text = "\n".join(
        [
            f"Title: {article.title}\nDescription: {article.description}"
            for article in news_results.articles[:10]  # Use more articles for R&D
        ]
    )

    prompt = f"""
    As a technology scout and R&D analyst, your task is to analyze the research and patent landscape
    for '{topic}'{f" with a focus on '{company}'" if company else ""}.

    Based *only* on the provided news articles and publications, generate a report in Markdown format.
    Address the following sections:

    1.  **Emerging Research:** What key publications, studies, or university research is mentioned?
    2.  **Patent Activity:** Are any new patents, filings, or patent-holders mentioned?
    3.  **Key Innovators:** Which companies, institutions, or researchers appear to be leading the R&D?
    4.  **Future Trajectory:** Based on the data, where is this research field heading?

    **News Articles & Publications:**
    ---
    {articles_text}
    ---
    """

    with console.status("[bold cyan]AI is analyzing R&D and patent data...[/bold cyan]"):
        ai_result = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return PatentRDResult(
            topic=topic,
            company=company,
            analysis_text="",
            error=f"AI analysis failed: {ai_result.error}",
        )

    return PatentRDResult(
        topic=topic, company=company, analysis_text=ai_result.analysis_text
    )


# +++ NEW FUNCTION +++
async def get_market_intelligence(
    product: str, industry: str, country: Optional[str] = None
) -> MarketIntelResult:
    """
    Gathers market intelligence, including pricing trends and competitor activity.

    Args:
        product (str): The specific product name (e.g., "iPhone 15").
        industry (str): The industry (e.g., "smartphone").
        country (str, optional): The country to focus on. Defaults to None.

    Returns:
        MarketIntelResult: A Pydantic model with the AI-generated analysis.
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return MarketIntelResult(
            product=product,
            industry=industry,
            country=country,
            analysis_text="",
            error="GNews and/or Google API key not found. Both are required for this analysis.",
        )

    location_scope = f"in {country}" if country else "globally"
    query = f'"{product}" pricing trends {location_scope} OR "{industry}" market competition {location_scope} OR "{product}" reviews'

    logger.info(f"Gathering data for market intelligence with query: {query}")
    news_results = await get_news_gnews(query, gnews_key)

    if not news_results or not news_results.articles:
        return MarketIntelResult(
            product=product,
            industry=industry,
            country=country,
            analysis_text="",
            error=f"Could not find any relevant news articles for the query: '{query}'.",
        )

    articles_text = "\n".join(
        [
            f"Title: {article.title}\nDescription: {article.description}"
            for article in news_results.articles[:10]
        ]
    )

    prompt = f"""
    As a competitive intelligence analyst, generate a market intelligence report for
    '{product}' in the '{industry}' industry, focusing {location_scope}.

    Based *only* on the provided news articles and reviews, generate a report in Markdown format.
    Address the following sections:

    1.  **Pricing Trends:** Are there any mentions of price changes, discounts, or pricing strategies?
    2.  **Competitor Activity:** What new product launches, marketing campaigns, or reviews are mentioned for competitors?
    3.  **Consumer Sentiment:** What do the articles and reviews suggest about customer opinions (e.g., positive, negative, key complaints, or praises)?
    4.  **Market Gaps & Opportunities:** Are any unaddressed needs or market gaps mentioned?

    **News Articles & Reviews:**
    ---
    {articles_text}
    ---
    """

    with console.status(
        "[bold cyan]AI is analyzing market trends and pricing...[/bold cyan]"
    ):
        ai_result = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return MarketIntelResult(
            product=product,
            industry=industry,
            country=country,
            analysis_text="",
            error=f"AI analysis failed: {ai_result.error}",
        )

    return MarketIntelResult(
        product=product,
        industry=industry,
        country=country,
        analysis_text=ai_result.analysis_text,
    )


# +++ NEW FUNCTION +++
async def monitor_esg_sustainability(
    company: str, industry: Optional[str] = None
) -> ESGMonitorResult:
    """
    Monitors ESG (Environmental, Social, Governance) and sustainability risks for a company.

    Args:
        company (str): The name of the company to analyze.
        industry (str, optional): The industry context. Defaults to None.

    Returns:
        ESGMonitorResult: A Pydantic model with the AI-generated analysis.
    """
    gnews_key = API_KEYS.gnews_api_key
    google_api_key = API_KEYS.google_api_key

    if not gnews_key or not google_api_key:
        return ESGMonitorResult(
            company=company,
            industry=industry,
            analysis_text="",
            error="GNews and/or Google API key not found. Both are required for this analysis.",
        )

    query = f'"{company}" ESG OR "{company}" "environmental social governance" OR "{company}" sustainability'
    if industry:
        query += f' OR "{industry}" ESG trends'

    logger.info(f"Gathering data for ESG monitoring with query: {query}")
    news_results = await get_news_gnews(query, gnews_key)

    if not news_results or not news_results.articles:
        return ESGMonitorResult(
            company=company,
            industry=industry,
            analysis_text="",
            error=f"Could not find any relevant news articles for the query: '{query}'.",
        )

    articles_text = "\n".join(
        [
            f"Title: {article.title}\nDescription: {article.description}"
            for article in news_results.articles[:10]
        ]
    )

    prompt = f"""
    As an ESG (Environmental, Social, Governance) risk analyst, your task is to provide an
    analysis of '{company}'s ESG and sustainability profile{f" within the '{industry}' industry" if industry else ""}.

    Based *only* on the provided news articles, generate a report in Markdown format.
    Address the following sections:

    1.  **Environmental (E):** What are the key mentions of environmental impact, carbon footprint, green initiatives, or environmental risks?
    2.  **Social (S):** What are the key mentions of labor practices, community engagement, data privacy, diversity, or social risks?
    3.  **Governance (G):** What are the key mentions of executive pay, board structure, transparency, bribery, scandals, or governance risks?
    4.  **Overall ESG Summary:** Provide a brief conclusion on the company's perceived ESG standing based on the articles.

    **News Articles:**
    ---
    {articles_text}
    ---
    """

    with console.status("[bold cyan]AI is analyzing ESG factors...[/bold cyan]"):
        ai_result = generate_swot_from_data(prompt, google_api_key)

    if ai_result.error:
        return ESGMonitorResult(
            company=company,
            industry=industry,
            analysis_text="",
            error=f"AI analysis failed: {ai_result.error}",
        )

    return ESGMonitorResult(
        company=company, industry=industry, analysis_text=ai_result.analysis_text
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


@industry_intel_app.command("stability-forecast")
def run_stability_forecast(
    country: str = typer.Argument(..., help="The target country to analyze."),
    region: Optional[str] = typer.Option(
        None, "--region", "-r", help="Optional specific region within the country."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Generates a political/social stability forecast for a country or region.
    """
    results_model = asyncio.run(get_stability_forecast(country, region))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Stability Forecast: {country.title()}{f' ({region.title()})' if region else ''}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))
    console.print(f"\nKey Factors Inspected: {results_model.key_factors['sources_found']}")

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{country}_{region}_stability" if region else f"{country}_stability"
        save_scan_to_db(
            target=target_name, module="industry_stability_forecast", data=results_dict
        )


# +++ NEW COMMAND +++
@industry_intel_app.command("patent-rd")
def run_patent_rd_tracking(
    topic: str = typer.Argument(
        ..., help="The industry, technology, or scientific field (e.g., 'graphene')."
    ),
    company: Optional[str] = typer.Option(
        None, "--company", help="A specific company to focus on."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors new patents, publications, and R&D for a topic.
    """
    results_model = asyncio.run(track_patent_rd(topic, company))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Patent & R&D Tracking: {topic.title()}{f' (Focus: {company.title()})' if company else ''}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{topic}_{company}_rd" if company else f"{topic}_rd"
        save_scan_to_db(
            target=target_name, module="industry_patent_rd", data=results_dict
        )


# +++ NEW COMMAND +++
@industry_intel_app.command("market-intel")
def run_market_intelligence(
    product: str = typer.Argument(..., help="The specific product name (e.g., 'iPhone 15')."),
    industry: str = typer.Argument(..., help="The industry (e.g., 'smartphone')."),
    country: Optional[str] = typer.Option(
        None, "--country", "-c", help="The country to focus the analysis on."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Gathers market intelligence, pricing trends, and competitor activity.
    """
    results_model = asyncio.run(get_market_intelligence(product, industry, country))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Market Intelligence: {product.title()} in {industry.title()}{f' ({country.title()})' if country else ''}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{product}_{industry}_market_intel"
        save_scan_to_db(
            target=target_name, module="industry_market_intel", data=results_dict
        )


# +++ NEW COMMAND +++
@industry_intel_app.command("esg-monitor")
def run_esg_monitoring(
    company: str = typer.Argument(..., help="The name of the company to analyze."),
    industry: Optional[str] = typer.Option(
        None, "--industry", "-i", help="The industry context."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors ESG (Environmental, Social, Governance) and sustainability risks.
    """
    results_model = asyncio.run(monitor_esg_sustainability(company, industry))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]ESG & Sustainability Monitor: {company.title()}[/bold] ---\n"
    )
    console.print(Markdown(results_model.analysis_text))

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target_name = f"{company}_esg"
        save_scan_to_db(target=target_name, module="industry_esg", data=results_dict)