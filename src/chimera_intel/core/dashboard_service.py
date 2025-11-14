"""
Service for aggregating and formatting data for the BI Dashboard.
"""

import logging
import re
from typing import Dict, Any, List
from chimera_intel.core.database import get_db
from chimera_intel.core.schemas import (
    SentimentTimeSeriesResult,
    SeoIntelResult,
)

logger = logging.getLogger(__name__)


def format_sentiment_time_series(
    results: List[SentimentTimeSeriesResult],
) -> Dict[str, Any]:
    """Formats sentiment data for a Plotly time-series chart."""
    if not results:
        return {}

    # Combine data from all sentiment scans for this target
    timestamps = []
    scores = []
    hints = []
    for res in results:
        for datapoint in res.time_series:
            if datapoint.timestamp != "UNKNOWN":
                timestamps.append(datapoint.timestamp)
                scores.append(datapoint.sentiment_score)
                hints.append(datapoint.document_hint)

    if not timestamps:
        return {}

    # Create a Plotly data object
    return {
        "data": [
            {
                "x": timestamps,
                "y": scores,
                "type": "scatter",
                "mode": "lines+markers",
                "name": "Sentiment",
                "text": hints,
                "marker": {"color": "blue"},
            }
        ],
        "layout": {
            "title": "Sentiment Over Time",
            "xaxis": {"title": "Date"},
            "yaxis": {
                "title": "Sentiment Score (-1.0 to 1.0)",
                "range": [-1, 1],
                "zeroline": True,
            },
            "hovermode": "closest",
        },
    }


def format_seo_keyword_ranking(
    results: List[SeoIntelResult],
) -> Dict[str, Any]:
    """Formats SEO keyword ranking data for a Plotly bar chart."""
    if not results:
        return {}

    # Use the most recent SEO scan
    latest_scan = sorted(results, key=lambda x: x.ran_at, reverse=True)[0]
    target_domain = latest_scan.target_domain
    keywords = []
    ranks = []
    urls = []

    for kw_analysis in latest_scan.keyword_analysis:
        keywords.append(kw_analysis.keyword)
        if kw_analysis.target_positions:
            # Target is ranking
            rank = kw_analysis.target_positions[0].rank
            ranks.append(rank)
            urls.append(kw_analysis.target_positions[0].url)
        else:
            # Target is not ranking
            ranks.append(0)  # Use 0 to indicate "Not in Top 10"
            urls.append("N/A")

    if not keywords:
        return {}

    # Create a Plotly data object
    return {
        "data": [
            {
                "x": keywords,
                "y": ranks,
                "type": "bar",
                "name": f"Rank for {target_domain}",
                "text": urls,
                "marker": {"color": "green"},
            }
        ],
        "layout": {
            "title": "Keyword Rankings (Top 10)",
            "xaxis": {"title": "Keyword"},
            "yaxis": {
                "title": "Rank (0 = Not in Top 10)",
                "autorange": "reversed",
                "tick0": 1,
                "dtick": 1,
            },
        },
    }


def _parse_visits(visits_str: str) -> float:
    """Helper to convert strings like '1.2M' or '300K' to float."""
    if not visits_str:
        return 0
    visits_str = visits_str.upper()
    try:
        if 'M' in visits_str:
            return float(re.sub(r"[^0-9\.]", "", visits_str)) * 1_000_000
        if 'K' in visits_str:
            return float(re.sub(r"[^0-9\.]", "", visits_str)) * 1_000
        return float(re.sub(r"[^0-9\.]", "", visits_str))
    except ValueError:
        return 0


def format_traffic_kpis(
    results: List[SeoIntelResult],
) -> Dict[str, Any]:
    """Formats traffic/authority data for Plotly 'indicator' charts."""
    if not results:
        return {}

    latest_scan = sorted(results, key=lambda x: x.ran_at, reverse=True)[0]
    if not latest_scan.traffic_authority:
        return {}

    traffic_data = latest_scan.traffic_authority
    rank = traffic_data.global_rank or 0
    visits = _parse_visits(traffic_data.estimated_visits or "0")

    return {
        "data": [
            {
                "type": "indicator",
                "mode": "gauge+number",
                "value": rank,
                "title": {"text": "Global Rank (Similarweb)"},
                "gauge": {
                    "axis": {"range": [None, 1], "autorange": "reversed"}
                },
                "domain": {"x": [0, 0.48], "y": [0, 1]},  # First plot
            },
            {
                "type": "indicator",
                "mode": "number",
                "value": visits,
                "title": {"text": "Est. Monthly Visits"},
                "number": {"prefix": "~"},
                "domain": {"x": [0.52, 1], "y": [0, 1]},  # Second plot
            },
        ],
        "layout": {
            "title": "Traffic & Authority KPIs",
            "grid": {"rows": 1, "columns": 2, "pattern": "independent"},
            "height": 250,  # Shorter height for KPIs
        },
    }


def format_content_velocity(
    results: List[SeoIntelResult],
) -> Dict[str, Any]:
    """Formats content velocity for a Plotly bar chart."""
    if not results:
        return {}

    latest_scan = sorted(results, key=lambda x: x.ran_at, reverse=True)[0]
    if (
        not latest_scan.content_velocity
        or not latest_scan.content_velocity.articles_per_month
    ):
        return {}

    velocity_data = latest_scan.content_velocity
    # Sort by date
    sorted_months = sorted(velocity_data.articles_per_month.keys())
    counts = [velocity_data.articles_per_month[m] for m in sorted_months]

    if not sorted_months:
        return {}

    return {
        "data": [
            {
                "x": sorted_months,
                "y": counts,
                "type": "bar",
                "name": "Articles",
                "marker": {"color": "orange"},
            }
        ],
        "layout": {
            "title": "Content Publishing Velocity",
            "xaxis": {"title": "Month"},
            "yaxis": {"title": "Articles Published"},
        },
    }


def format_topic_coverage(
    results: List[SeoIntelResult],
) -> Dict[str, Any]:
    """Formats topic coverage for a Plotly pie chart."""
    if not results:
        return {}

    latest_scan = sorted(results, key=lambda x: x.ran_at, reverse=True)[0]
    if (
        not latest_scan.topic_coverage
        or not latest_scan.topic_coverage.clusters
    ):
        return {}

    cluster_data = latest_scan.topic_coverage
    labels = list(cluster_data.clusters.keys())
    values = [len(docs) for docs in cluster_data.clusters.values()]

    if not labels:
        return {}

    return {
        "data": [
            {
                "labels": labels,
                "values": values,
                "type": "pie",
                "textinfo": "label+percent",
                "insidetextorientation": "radial",
            }
        ],
        "layout": {
            "title": "Content Topic Coverage",
        },
    }


def get_dashboard_charts(target: str) -> Dict[str, Dict[str, Any]]:
    """
    Fetches all analysis data for a target and formats it for the dashboard.
    """
    charts = {}
    db_gen = get_db()
    db = next(db_gen)
    try:
        # 1. Fetch Sentiment Data
        sentiment_results_raw = (
            db.query(SentimentTimeSeriesResult)
            .filter(SentimentTimeSeriesResult.target == target)
            .all()
        )
        if sentiment_results_raw:
            charts["sentiment"] = format_sentiment_time_series(
                sentiment_results_raw
            )

        # 2. Fetch SEO Data (ONCE)
        seo_results_raw = (
            db.query(SeoIntelResult)
            .filter(SeoIntelResult.target_domain == target)
            .all()
        )

        if seo_results_raw:
            charts["seo_keywords"] = format_seo_keyword_ranking(
                seo_results_raw
            )
            charts["traffic_kpis"] = format_traffic_kpis(seo_results_raw)
            charts["content_velocity"] = format_content_velocity(
                seo_results_raw
            )
            charts["topic_coverage"] = format_topic_coverage(
                seo_results_raw
            )

        # ... (Future charts like pricing_intel, business_intel_stocks, etc.)

    except Exception as e:
        logger.error(f"Error fetching dashboard data: {e}")
    finally:
        db.close()

    return charts