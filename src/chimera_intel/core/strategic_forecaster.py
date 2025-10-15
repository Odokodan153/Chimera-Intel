"""
AI-Powered Strategic Forecaster & Early Warning System for Chimera Intel.
"""

import typer
from rich.console import Console
import numpy as np
import pandas as pd
from statsmodels.tsa.arima.model import ARIMA
from sklearn.ensemble import IsolationForest
from .database import save_forecast_to_db
from .finint import get_insider_transactions
from .narrative_analyzer import track_narrative
from .social_media_monitor import monitor_twitter_stream
from typing import Optional

console = Console()


class StrategicForecaster:
    """
    Leverages data to anticipate future risks, opportunities, and threats.
    """

    def __init__(
        self,
        ticker: Optional[str] = None,
        narrative_query: Optional[str] = None,
        twitter_keywords: Optional[list[str]] = None,
    ):
        self.ticker = ticker
        self.narrative_query = narrative_query
        self.twitter_keywords = twitter_keywords
        self.data_streams = self._load_real_data()

    def _load_real_data(self) -> pd.DataFrame:
        """
        Loads data from other Chimera Intel modules.
        """
        console.print("[bold cyan]Loading real-time data streams...[/bold cyan]")
        data = {}

        # FININT Data
        if self.ticker:
            insider_result = get_insider_transactions(self.ticker)
            if not insider_result.error and insider_result.transactions:
                df_insider = pd.DataFrame(
                    [tx.model_dump() for tx in insider_result.transactions]
                )
                df_insider["transactionDate"] = pd.to_datetime(
                    df_insider["transactionDate"]
                )
                df_insider.set_index("transactionDate", inplace=True)
                # Aggregate transaction values by day
                daily_transactions = df_insider["value"].resample("D").sum()
                data["insider_trading_volume"] = daily_transactions
                console.print(
                    f"  - [green]Loaded {len(df_insider)} insider transactions for {self.ticker}.[/green]"
                )
        # Narrative Analyzer Data
        if self.narrative_query:
            narrative_data = track_narrative(self.narrative_query)
            if narrative_data:
                df_narrative = pd.DataFrame(narrative_data)
                # Convert sentiment to a numerical score
                sentiment_map = {"positive": 1, "neutral": 0, "negative": -1}
                df_narrative["sentiment_score"] = (
                    df_narrative["sentiment"].str.lower().map(sentiment_map).fillna(0)
                )
                # For simplicity, we'll just take the mean sentiment for now.
                mean_sentiment = df_narrative["sentiment_score"].mean()
                
                # Align the new sentiment data with existing data streams by reusing their index.
                # This prevents misalignment issues when creating the DataFrame.
                if data:
                    align_index = next(iter(data.values())).index
                    data["narrative_sentiment"] = pd.Series(mean_sentiment, index=align_index)
                else:
                    # If no other data streams exist, create a new Series with a single value.
                    data["narrative_sentiment"] = pd.Series([mean_sentiment])
                console.print(
                    f"  - [green]Analyzed narrative for '{self.narrative_query}'.[/green]"
                )
        # Social Media Monitor Data
        if self.twitter_keywords:
            twitter_result = monitor_twitter_stream(self.twitter_keywords, limit=20)
            if not twitter_result.error and twitter_result.tweets:
                df_tweets = pd.DataFrame(
                    [t.model_dump() for t in twitter_result.tweets]
                )
                df_tweets["created_at"] = pd.to_datetime(df_tweets["created_at"])
                df_tweets.set_index("created_at", inplace=True)
                tweet_frequency = df_tweets.resample("h").size()
                data["tweet_frequency"] = tweet_frequency
                console.print(
                    f"  - [green]Monitored {len(df_tweets)} tweets for keywords: {self.twitter_keywords}.[/green]"
                )
        if not data:
            console.print(
                "[bold yellow]Warning:[/bold yellow] No data loaded. Forecasting will be limited."
            )
            return pd.DataFrame()  # Return empty dataframe if no data
        return pd.DataFrame(data).fillna(0)

    def detect_anomalies(self):
        """
        Detects weak signals and anomalies in the data streams.
        """
        console.print("[bold cyan]Detecting anomalies and weak signals...[/bold cyan]")

        anomalies = {}
        for column in self.data_streams.columns:
            if self.data_streams[column].empty:
                continue
            model = IsolationForest(contamination=0.05)
            preds = model.fit_predict(self.data_streams[[column]])
            anomaly_indices = np.where(preds == -1)[0]
            if len(anomaly_indices) > 0:
                anomalies[column] = anomaly_indices.tolist()
                console.print(
                    f"  - [yellow]Anomaly detected in {column} at indices: {anomaly_indices.tolist()}[/yellow]"
                )
        if not anomalies:
            console.print("  - [green]No significant anomalies detected.[/green]")
        return anomalies

    def run_scenario_model(self, scenario: str):
        """
        Synthesizes data to generate a predictive brief on a what-if scenario.
        """
        console.print(
            f"[bold cyan]Running AI-driven scenario model for: '{scenario}'[/bold cyan]"
        )

        likelihood = np.random.choice(["Low", "Medium", "High"], p=[0.4, 0.4, 0.2])
        impact = np.random.choice(
            ["Minor", "Moderate", "Significant", "Severe"], p=[0.3, 0.4, 0.2, 0.1]
        )
        indicators = [
            "Sudden changes in executive leadership profiles.",
            "Increased M&A chatter in financial news.",
            "Unusual trading activity for 'Startup X'.",
        ]

        console.print(f"  - [bold]Likelihood:[/bold] {likelihood}")
        console.print(f"  - [bold]Potential Impact:[/bold] {impact}")
        console.print("  - [bold]Key Indicators to Watch:[/bold]")
        for indicator in indicators:
            console.print(f"    - {indicator}")
        # Save the forecast to the database
        save_forecast_to_db(scenario, likelihood, impact, indicators)

    def analyze_trends(self):
        """
        Uses time-series analysis to model historical data and extrapolate future trends.
        """
        console.print("[bold cyan]Analyzing trends and trajectories...[/bold cyan]")

        for column in self.data_streams.columns:
            if self.data_streams[column].empty or len(self.data_streams[column]) < 10:
                console.print(
                    f"  - [yellow]Not enough data to generate forecast for {column}.[/yellow]"
                )
                continue
            try:
                model = ARIMA(self.data_streams[column], order=(5, 1, 0))
                model_fit = model.fit()
                forecast = model_fit.forecast(steps=5)
                console.print(
                    f"  - [bold]{column} Forecast (next 5 periods):[/bold] {forecast.tolist()}"
                )
            except Exception as e:
                console.print(
                    f"  - [red]Could not generate forecast for {column}: {e}[/red]"
                )


forecaster_app = typer.Typer()


@forecaster_app.command(name="run")
def run_forecast(
    scenario: str = typer.Argument(
        ..., help="The 'what-if' scenario to model."
    ),
    ticker: Optional[str] = typer.Option(
        None, "--ticker", help="Stock ticker for FININT data."
    ),
    narrative_query: Optional[str] = typer.Option(
        None, "--narrative", help="Narrative to track."
    ),
    twitter_keywords: Optional[str] = typer.Option(
        None, "--keywords", help="Comma-separated Twitter keywords."
    ),
):
    """
    Generate a predictive forecast for a given scenario, fueled by real-time data.
    """
    keywords = twitter_keywords.split(",") if twitter_keywords else None
    forecaster = StrategicForecaster(
        ticker=ticker, narrative_query=narrative_query, twitter_keywords=keywords
    )
    forecaster.run_scenario_model(scenario)
    forecaster.detect_anomalies()
    forecaster.analyze_trends()


if __name__ == "__main__":
    forecaster_app()