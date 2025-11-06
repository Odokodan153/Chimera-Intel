"""
Cognitive Warfare & Narrative Shield Engine for Chimera Intel.
Analyzes and counters influence operations and weaponized narratives.
"""

import typer
import json
import logging
from rich.console import Console
import pandas as pd
from typing import Optional, List, Dict, Any
import re

# --- (REAL) Core Module Imports ---
from .narrative_analyzer import track_narrative_gnews
from .social_media_monitor import search_twitter
from .humint import HumintScenario, run_humint_scenario
from .config_loader import API_KEYS
from .ai_core import generate_swot_from_data
# --- End (REAL) Imports ---

console = Console()
logger = logging.getLogger(__name__)

# A simplified model of psychological triggers for demonstration purposes.
# This is now the FALLBACK logic.
PSYCHOLOGICAL_TRIGGERS_RULES = {
    "fear": [
        "panic", "threat", "danger", "risk", "warning", "collapse", "afraid", "fear",
        "lockdown", "vulnerable", "crisis"
    ],
    "anger": [
        "outrage", "injustice", "betrayal", "hate", "fury", "corrupt", "unacceptable",
        "rigged", "stolen", "disgusted"
    ],
    "tribalism": [
        "us vs them", "they are", "we are", "our people", "elite", "globalist",
        "real patriots", "the enemy", "us", "them"
    ],
    "hope": ["solution", "breakthrough", "promise", "future", "optimism", "unity", "healing"],
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
        self.api_key = API_KEYS.google_api_key
        self.narratives_df = self._load_narratives()

    def _load_narratives(self) -> pd.DataFrame:
        """(REAL) Loads narratives from Chimera Intel modules."""
        console.print(
            "[bold cyan]Loading narratives from multiple ecosystems...[/bold cyan]"
        )
        all_narratives = []

        # (REAL) Narrative Analyzer Data (e.g., news, blogs)
        if API_KEYS.gnews_api_key:
            try:
                # Use the REAL function
                narrative_result = track_narrative_gnews(self.narrative_query)
                if narrative_result.articles:
                    for item in narrative_result.articles:
                        item["source"] = "Web/News"
                    all_narratives.extend(narrative_result.articles)
                    console.print(
                        f"  - [green]Loaded {len(narrative_result.articles)} narratives from web sources.[/green]"
                    )
            except Exception as e:
                logger.error(f"Failed to load GNews narratives: {e}")
                
        # (REAL) Social Media Monitor Data (e.g., Twitter)
        if self.twitter_keywords and API_KEYS.twitter_bearer_token:
            try:
                # Use the REAL function
                twitter_result = search_twitter(self.twitter_keywords, limit=20)
                if not twitter_result.error and twitter_result.tweets:
                    tweets_data = [
                        {
                            "content": t.text, 
                            "sentiment": "unknown", 
                            "source": "Twitter",
                            "author": t.author_username,
                            "url": t.url
                        }
                        for t in twitter_result.tweets
                    ]
                    all_narratives.extend(tweets_data)
                    console.print(
                        f"  - [green]Loaded {len(tweets_data)} narratives from Twitter.[/green]"
                    )
            except Exception as e:
                logger.error(f"Failed to load Twitter narratives: {e}")

        if not all_narratives:
            console.print(
                "[bold yellow]Warning: No narratives loaded. Analysis will be limited.[/bold yellow]"
            )
            return pd.DataFrame()
            
        # Standardize 'content' key
        df = pd.DataFrame(all_narratives)
        if "text" in df.columns and "content" not in df.columns:
            df.rename(columns={"text": "content"}, inplace=True)
            
        return df

    def analyze_narratives(self):
        """
        Identifies triggers and maps the flow of narratives.
        """
        if self.narratives_df.empty:
            return
        console.print(
            "\n[bold cyan]Analyzing cognitive triggers and narrative flow...[/bold cyan]"
        )
        
        # Identify Triggers
        with console.status("[bold green]Analyzing psychological triggers...[/bold green]"):
            self.narratives_df["triggers"] = self.narratives_df["content"].apply(
                self._identify_triggers
            )

        # Map Flow (Conceptual)
        source_counts = self.narratives_df["source"].value_counts().to_dict()
        console.print("  - [bold]Narrative Flow Map (Sources):[/bold]")
        for source, count in source_counts.items():
            console.print(f"    - {source}: {count} narratives detected.")
            
        # Report on Triggers
        detected_triggers = self.narratives_df["triggers"].explode().dropna().unique()
        console.print("  - [bold]Detected Cognitive Triggers:[/bold]")
        if not detected_triggers.any():
            console.print("    - [green]No strong triggers detected.[/green]")
        for trigger in detected_triggers:
            console.print(f"    - [yellow]{trigger.capitalize()}[/yellow]")

    def _identify_triggers_rules(self, content: str) -> List[str]:
        """(FALLBACK) Identifies psychological triggers in a text using keywords."""
        triggers_found = []
        content_lower = content.lower()
        for trigger, keywords in PSYCHOLOGICAL_TRIGGERS_RULES.items():
            try:
                pattern = r"\b(" + "|".join(re.escape(k) for k in keywords) + r")\b"
                if re.search(pattern, content_lower, re.IGNORECASE):
                    triggers_found.append(trigger)
            except re.error as e:
                console.print(f"[red]Regex error for trigger '{trigger}': {e}[/red]")
        return triggers_found

    def _identify_triggers(self, content: str) -> List[str]:
        """(REAL) Identifies triggers using AI, with a rule-based fallback."""
        if not self.api_key:
            return self._identify_triggers_rules(content)
            
        prompt = f"""
        Analyze the following text for psychological triggers.
        Classify the text based on the *primary* trigger it uses from this list:
        ['fear', 'anger', 'tribalism', 'hope', 'none']
        
        Text:
        "{content[:1000]}"
        
        Return a single JSON object with one key, "triggers",
        containing a list of the triggers found (e.g., {{"triggers": ["fear", "tribalism"]}}).
        If no strong trigger is found, return {{"triggers": ["none"]}}.
        
        Return ONLY the valid JSON object.
        """
        try:
            # Re-use the generic AI function
            ai_result = generate_swot_from_data(prompt, self.api_key)
            if ai_result.error:
                raise Exception(ai_result.error)
            
            json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
            data = json.loads(json_text)
            triggers = data.get("triggers", [])
            return [t for t in triggers if t != "none"] # Filter out 'none'
            
        except Exception as e:
            logger.warning(f"AI trigger detection failed: {e}. Falling back to rules.")
            return self._identify_triggers_rules(content)

    def generate_narrative_shield(self):
        """
        Generates counter-narratives to inoculate against disinformation.
        """
        if self.narratives_df.empty or "triggers" not in self.narratives_df.columns:
            return
        console.print(
            "\n[bold cyan]Generating Narrative Shield (Counter-Narratives)...[/bold cyan]"
        )

        dominant_trigger_series = self.narratives_df["triggers"].explode().mode()
        
        if dominant_trigger_series.empty:
            trigger_key = "default"
        else:
            trigger_key = dominant_trigger_series[0]

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
    twitter_keywords = keywords.split(",") if keywords else []
    
    # Adapt keyword list for Twitter search (which is what search_twitter uses)
    twitter_query_list = [f'"{kw}"' for kw in twitter_keywords] + [f'"{narrative_query}"']
    
    engine = CognitiveWarfareEngine(
        narrative_query=narrative_query, twitter_keywords=twitter_query_list
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
    objective: str = typer.Option(
        ..., "--objective", "-o", help="Objective of the operation."
    ),
    cover_story: Optional[str] = typer.Option(
        None, "--cover", "-c", help="Cover story to be used."
    ),
):
    """
    (REAL) Run an AI-powered HUMINT scenario against a target.
    """
    console.print(
        f"[bold cyan]Running HUMINT scenario '{scenario_type}' against '{target}'...[/bold cyan]"
    )

    try:
        scenario = HumintScenario(
            scenario_type=scenario_type, 
            target=target, 
            objective=objective, 
            cover_story=cover_story
        )
        
        # Call the REAL function from humint.py
        with console.status("[bold cyan]Running AI simulation...[/bold cyan]"):
            result = run_humint_scenario(scenario)

        console.print_json(data=result)
        
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