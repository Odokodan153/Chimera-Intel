import typer
import os
import json
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# --- AI Model Initializations ---

# Note: The first time you run this, transformers will download the model, which may take time.
# This setup is wrapped in a try-except block to handle cases where the libraries might not be installed.
try:
    from transformers import pipeline
    # Initialize a pipeline for sentiment analysis
    sentiment_analyzer = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
except ImportError:
    sentiment_analyzer = None

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None


console = Console()

# --- AI Core Functions ---

def analyze_sentiment(text: str) -> dict:
    """Analyzes the sentiment of a given text using a local transformer model."""
    if not sentiment_analyzer:
        return {"error": "The 'transformers' or 'torch' library is not installed. Cannot perform sentiment analysis."}
    try:
        # The pipeline returns a list with a dictionary
        result = sentiment_analyzer(text)
        return result[0]
    except Exception as e:
        return {"error": f"An error occurred during sentiment analysis: {e}"}

def generate_swot_from_data(json_data_str: str, api_key: str) -> str:
    """Uses a Generative AI model (Gemini Pro) to create a SWOT analysis from collected data."""
    if not api_key:
        return "Error: GOOGLE_API_KEY not found in .env file."
        
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    
    prompt = f"""
    Based on the following OSINT data collected for a company, please perform a SWOT analysis (Strengths, Weaknesses, Opportunities, Threats).
    Present the output in Markdown format. Be concise and base your analysis strictly on the data provided.

    OSINT Data:
    {json_data_str}
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"An error occurred with the Google AI API: {e}"

def detect_traffic_anomalies(traffic_data: list) -> dict:
    """Uses Isolation Forest to detect anomalies in a time series of website traffic."""
    if not IsolationForest:
        return {"error": "The 'scikit-learn' library is not installed. Cannot perform anomaly detection."}
    
    # Expects a list of numbers (e.g., monthly visits)
    if not traffic_data or not all(isinstance(x, (int, float)) for x in traffic_data):
        return {"error": "Invalid input. Please provide a list of numbers for traffic data."}
        
    try:
        # Scikit-learn expects a 2D array
        data_array = np.array(traffic_data).reshape(-1, 1)
        
        # The "contamination" parameter is an estimate of the proportion of outliers.
        # 'auto' is a good default.
        clf = IsolationForest(contamination='auto', random_state=42)
        predictions = clf.fit_predict(data_array)
        
        # The model predicts 1 for inliers and -1 for outliers (anomalies).
        anomalies = [traffic_data[i] for i, pred in enumerate(predictions) if pred == -1]
        
        return {
            "data_points": traffic_data,
            "detected_anomalies": anomalies,
            "message": "Anomalies are data points considered unusual compared to the rest of the dataset."
        }
    except Exception as e:
        return {"error": f"An error occurred during anomaly detection: {e}"}

# --- Typer CLI Application for this module ---

ai_app = typer.Typer()

@ai_app.command("sentiment")
def run_sentiment_analysis(text: str = typer.Argument(..., help="A block of text (like a news headline or review) to analyze.")):
    """Analyzes the sentiment of a piece of text."""
    console.print(Panel(f"[bold blue]Analyzing Sentiment For:[/] '{text[:100]}...'", border_style="magenta"))
    result = analyze_sentiment(text)
    console.print(result)
    
@ai_app.command("swot")
def run_swot_analysis(
    input_file: str = typer.Argument(..., help="Path to a JSON file containing collected OSINT data (e.g., from a 'scan' command).")
):
    """Generates a SWOT analysis from a JSON data file."""
    console.print(Panel(f"[bold blue]Generating SWOT Analysis from:[/] {input_file}", border_style="magenta"))
    
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        console.print("[bold red]Error: GOOGLE_API_KEY not found in .env file.[/bold red]")
        raise typer.Exit(code=1)
        
    try:
        with open(input_file, 'r') as f:
            data_str = f.read()
    except FileNotFoundError:
        console.print(f"[bold red]Error: Input file not found at {input_file}[/bold red]")
        raise typer.Exit(code=1)
    
    swot_markdown = generate_swot_from_data(data_str, api_key)
    console.print(Markdown(swot_markdown))

@ai_app.command("anomaly")
def run_anomaly_detection(
    data_points: str = typer.Argument(..., help="A comma-separated list of numbers (e.g., '100,110,105,250,90').")
):
    """Detects anomalies in a numerical dataset."""
    console.print(Panel("[bold blue]Detecting Anomalies in Dataset[/bold blue]", border_style="magenta"))
    try:
        # Convert the comma-separated string to a list of integers
        numeric_data = [int(p.strip()) for p in data_points.split(',')]
        result = detect_traffic_anomalies(numeric_data)
        console.print(JSON(json.dumps(result, indent=4)))
    except ValueError:
        console.print("[bold red]Error: Please provide a valid comma-separated list of numbers.[/bold red]")
        raise typer.Exit(code=1)