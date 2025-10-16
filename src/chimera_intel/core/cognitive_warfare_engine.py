"""
Cognitive Warfare & Narrative Shield Engine for Chimera Intel.
Analyzes and counters influence operations and weaponized narratives.
"""

import typer
from rich.console import Console
import pandas as pd
from typing import Optional, List
from .narrative_analyzer import track_narrative
from .social_media_monitor import monitor_twitter_stream

# Import HUMINT scenario components


from .humint import HumintScenario, run_humint_scenario

console = Console()

# A simplified model of psychological triggers for demonstration purposes.


PSYCHOLOGICAL_TRIGGERS = {
    "fear": ["panic", "threat", "danger", "risk", "warning", "collapse", "afraid"],
    "anger": [
        "outrage",
        "injustice",
        "betrayal",
        "hate",
        "fury",
        "corrupt",
        "unacceptable",
    ],
    "tribalism": [
        "us vs them",
        "they are",
        "we are",
        "our people",
        "elite",
        "globalist",
    ],
    "hope": ["solution", "breakthrough", "promise", "future", "optimism", "unity"],
}

# Templates for generating counter-narratives.


COUNTER_NARRATIVE_TEMPLATES = {
    "fear": "While concerns about '{topic}' are noted, focusing on verifiable facts and data provides a clearer picture and helps mitigate unnecessary alarm.",
    "anger": "The strong emotions surrounding '{topic}' are understandable. A productive path forward involves channeling this energy into constructive dialogue and fact-based solutions.",
    "tribalism": "The narrative of 'us vs. them' regarding '{topic}' is a divisive oversimplification. This is a multifaceted issue that requires collaboration, not conflict, to address effectively.",
    "default": "A balanced perspective on '{topic}' requires examining multiple sources and challenging emotionally charged claims with objective evidence.",
}


class CognitiveWarfareEngine:
    """
    Analyzes and counters weaponized narratives using NLP and psychological modeling.
    """

    def __init__(
        self, narrative_query: str, twitter_keywords: Optional[List[str]] = None
    ):
        self.narrative_query = narrative_query
        self.twitter_keywords = twitter_keywords
        self.narratives = self._load_narratives()

    def _load_narratives(self) -> pd.DataFrame:
        """Loads narratives from Chimera Intel modules."""
        console.print(
            "[bold cyan]Loading narratives from multiple ecosystems...[/bold cyan]"
        )
        all_narratives = []

        # Narrative Analyzer Data (e.g., news, blogs)

        narrative_data = track_narrative(self.narrative_query)
        if narrative_data:
            for item in narrative_data:
                item["source"] = "Web/News"
            all_narratives.extend(narrative_data)
            console.print(
                f"  - [green]Loaded {len(narrative_data)} narratives from web sources.[/green]"
            )
        # Social Media Monitor Data (e.g., Twitter)

        if self.twitter_keywords:
            twitter_result = monitor_twitter_stream(self.twitter_keywords, limit=20)
            if not twitter_result.error and twitter_result.tweets:
                tweets_data = [
                    {"content": t.text, "sentiment": "unknown", "source": "Twitter"}
                    for t in twitter_result.tweets
                ]
                all_narratives.extend(tweets_data)
                console.print(
                    f"  - [green]Loaded {len(tweets_data)} narratives from Twitter.[/green]"
                )
        if not all_narratives:
            console.print(
                "[bold yellow]Warning: No narratives loaded. Analysis will be limited.[/bold yellow]"
            )
            return pd.DataFrame()
        return pd.DataFrame(all_narratives)

    def analyze_narratives(self):
        """
        Identifies triggers and maps the flow of narratives.
        """
        if self.narratives.empty:
            return
        console.print(
            "\n[bold cyan]Analyzing cognitive triggers and narrative flow...[/bold cyan]"
        )

        # Identify Triggers

        self.narratives["triggers"] = self.narratives["content"].apply(
            self._identify_triggers
        )

        # Map Flow (Conceptual)

        source_counts = self.narratives["source"].value_counts().to_dict()
        console.print("  - [bold]Narrative Flow Map (Sources):[/bold]")
        for source, count in source_counts.items():
            console.print(f"    - {source}: {count} narratives detected.")
        # Report on Triggers

        detected_triggers = self.narratives["triggers"].explode().dropna().unique()
        console.print("  - [bold]Detected Cognitive Triggers:[/bold]")
        for trigger in detected_triggers:
            console.print(f"    - [yellow]{trigger.capitalize()}[/yellow]")

    def _identify_triggers(self, content: str) -> List[str]:
        """Identifies psychological triggers in a text."""
        triggers_found = []
        for trigger, keywords in PSYCHOLOGICAL_TRIGGERS.items():
            if any(keyword in content.lower() for keyword in keywords):
                triggers_found.append(trigger)
        return triggers_found

    def generate_narrative_shield(self):
        """
        Generates counter-narratives to inoculate against disinformation.
        """
        if self.narratives.empty or "triggers" not in self.narratives.columns:
            return
        console.print(
            "\n[bold cyan]Generating Narrative Shield (Counter-Narratives)...[/bold cyan]"
        )

        dominant_trigger = self.narratives["triggers"].explode().mode()

        if dominant_trigger.empty:
            trigger_key = "default"
        else:
            trigger_key = dominant_trigger[0]
        template = COUNTER_NARRATIVE_TEMPLATES.get(
            trigger_key, COUNTER_NARRATIVE_TEMPLATES["default"]
        )
        counter_narrative = template.format(topic=self.narrative_query)

        console.print(
            f"  - [bold]Dominant Trigger:[/bold] [yellow]{trigger_key.capitalize()}[/yellow]"
        )
        console.print("  - [bold]Generated 'Digital Antibody':[/bold]")
        console.print(f'    [green i]"{counter_narrative}"[/green i]')


cognitive_warfare_app = typer.Typer()


@cognitive_warfare_app.command(name="deploy-shield")
def deploy_shield(
    narrative_query: str = typer.Option(
        ..., "--narrative", help="The core narrative topic to analyze and counter."
    ),
    keywords: Optional[str] = typer.Option(
        None, "--keywords", help="Comma-separated keywords for social media tracking."
    ),
):
    """
    Analyze a narrative, identify its psychological exploits, and generate a counter-narrative shield.
    """
    twitter_keywords = keywords.split(",") if keywords else None
    engine = CognitiveWarfareEngine(
        narrative_query=narrative_query, twitter_keywords=twitter_keywords
    )
    engine.analyze_narratives()
    engine.generate_narrative_shield()


@cognitive_warfare_app.command(name="run_scenario")
def run_scenario_command(
    scenario_type: str = typer.Option(
        ...,
        "--scenario-type",
        help="Type of HUMINT scenario to run (e.g., 'infiltration', 'elicitation').",
    ),
    target: str = typer.Option(
        ..., "--target", help="The target of the HUMINT scenario."
    ),
):
    """
    Run a HUMINT scenario against a target.
    """
    console.print(
        f"[bold cyan]Running HUMINT scenario '{scenario_type}' against '{target}'...[/bold cyan]"
    )

    try:
        scenario = HumintScenario(scenario_type=scenario_type, target=target)
        result = run_humint_scenario(scenario)

        if result.get("success"):
            console.print(
                f"  - [green]Scenario successful:[/green] {result.get('outcome')}"
            )
        else:
            console.print(f"  - [red]Scenario failed:[/red] {result.get('outcome')}")
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {e}")


if __name__ == "__main__":
    cognitive_warfare_app()
