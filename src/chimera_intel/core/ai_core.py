import typer
import os
import json
import google.generativeai as genai
from rich.panel import Panel
from rich.markdown import Markdown
from .utils import console, save_or_print_results

# --- AI Model Initializations ---
try:
    from transformers import pipeline
    sentiment_analyzer = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")
except ImportError:
    sentiment_analyzer = None

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None

def analyze_sentiment(text: str) -> dict:
    """Analyzes the sentiment of a given text using a local transformer model.

    Args:
        text (str): The text to analyze.

    Returns:
        dict: A dictionary containing the sentiment label and score, or an error.
    """
    if not sentiment_analyzer:
        return {"error": "'transformers' or 'torch' not installed."}
    try:
        return sentiment_analyzer(text)[0]
    except Exception as e:
        return {"error": f"Sentiment analysis error: {e}"}

def generate_swot_from_data(json_data_str: str, api_key: str) -> str:
    """Uses a Generative AI model (Gemini Pro) to create a SWOT analysis.

    Args:
        json_data_str (str): A string containing the JSON OSINT data.
        api_key (str): The Google AI API key.

    Returns:
        str: A markdown-formatted SWOT analysis, or an error message.
    """
    if not api_key:
        return "Error: GOOGLE_API_KEY not found."
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    prompt = f"""Based on the following OSINT data, perform a SWOT analysis. 
    Present the output in Markdown format.
    OSINT Data: {json_data_str}"""
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Google AI API error: {e}"

def detect_traffic_anomalies(traffic_data: list) -> dict:
    """Uses Isolation Forest to detect anomalies in a time series of website traffic.

    Args:
        traffic_data (list): A list of numbers (e.g., monthly visits).

    Returns:
        dict: A dictionary containing the original data and detected anomalies, or an error.
    """
    if not IsolationForest:
        return {"error": "'scikit-learn' not installed."}
    if not all(isinstance(x, (int, float)) for x in traffic_data):
        return {"error": "Invalid input. Please provide a list of numbers."}
    try:
        data_array = np.array(traffic_data).reshape(-1, 1)
        clf = IsolationForest(contamination='auto', random_state=42)
        predictions = clf.fit_predict(data_array)
        anomalies = [traffic_data[i] for i, pred in enumerate(predictions) if pred == -1]
        return {"data_points": traffic_data, "detected_anomalies": anomalies}
    except Exception as e:
        return {"error": f"Anomaly detection error: {e}"}


ai_app = typer.Typer()

@ai_app.command("sentiment")
def run_sentiment_analysis(text: str):
    """Analyzes the sentiment of a piece of text."""
    console.print(Panel(f"[bold magenta]Analyzing Sentiment For:[/] '{text[:100]}...'", title="AI Core | Sentiment"))
    result = analyze_sentiment(text)
    save_or_print_results(result, None)

@ai_app.command("swot")
def run_swot_analysis(input_file: str):
    """Generates a SWOT analysis from a JSON data file."""
    console.print(Panel(f"[bold magenta]Generating SWOT Analysis from:[/] {input_file}", title="AI Core | SWOT"))
    api_key = os.getenv("GOOGLE_API_KEY")
    try:
        with open(input_file, 'r') as f: data_str = f.read()
        swot_markdown = generate_swot_from_data(data_str, api_key)
        console.print(Markdown(swot_markdown))
    except FileNotFoundError:
        console.print(f"[bold red]Error: Input file not found at {input_file}[/bold red]")

@ai_app.command("anomaly")
def run_anomaly_detection(data_points: str):
    """Detects anomalies in a numerical dataset (e.g., '100,110,250,90')."""
    console.print(Panel("[bold magenta]Detecting Anomalies in Dataset[/bold magenta]", title="AI Core | Anomaly"))
    try:
        numeric_data = [int(p.strip()) for p in data_points.split(',')]
        result = detect_traffic_anomalies(numeric_data)
        save_or_print_results(result, None)
    except ValueError:
        console.print("[bold red]Error: Please provide a valid comma-separated list of numbers.[/bold red]")