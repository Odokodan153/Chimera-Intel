# Chimera Intel 🔱

A modular OSINT platform for comprehensive corporate intelligence and counter-intelligence, powered by an AI analysis core.

[Image of a network graph with interconnected nodes]

## Overview

Chimera Intel is a command-line tool designed to solve a critical business problem: information fragmentation. Inspired by the mythological Chimera—a creature forged from multiple animals—this tool synthesizes disparate data streams (technical footprints, financial records, web traffic, code leaks, and more) into a single, unified, and actionable dossier.

It is built to serve two primary functions:
* **Offensive Intelligence:** To gather a deep understanding of external entities like competitors or potential partners.
* **Defensive Counter-Intelligence:** To allow an organization to see its own digital footprint through the eyes of an attacker and proactively identify weaknesses.

## Features

Chimera Intel is organized into three main modules, each with a suite of commands.

###  SCAN (Offensive Intelligence)
-   `scan footprint`: Gathers WHOIS, DNS, and Subdomain information.
-   `scan web`: Analyzes a website's technology stack (BuiltWith) and traffic estimates (Similarweb).
-   `scan business`: Retrieves public financial data (Yahoo Finance), news articles (GNews), and patent filings.

### DEFENSIVE (Counter-Intelligence)
-   `defensive breaches`: Checks for domain-related email breaches via HIBP.
-   `defensive leaks`: Scans GitHub for potential secret leaks.
-   `defensive typosquat`: Detects potential phishing domains with dnstwist.
-   `defensive surface`: Analyzes public-facing assets using Shodan.
-   `defensive pastebin`: Searches Pastebin dumps for specific keywords.
-   `defensive ssllabs`: Performs an in-depth SSL/TLS server test.
-   `defensive mobsf`: Analyzes Android `.apk` files using a local MobSF instance.

### AI (Analysis Core)
-   `ai sentiment`: Analyzes the sentiment of a news headline or text using a local transformer model.
-   `ai swot`: Automatically generates a SWOT analysis from collected data using the Google Gemini Pro API.
-   `ai anomaly`: Detects anomalies in numerical data series using Scikit-learn.

## Setup & Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/chimera-intel.git](https://github.com/your-username/chimera-intel.git)
    cd chimera-intel
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3.  **Set up API Keys:**
    -   Create a `.env` file in the root directory.
    -   Open the `.env` file and add your API keys from the various services used (VirusTotal, Shodan, Google AI, HIBP, GitHub, etc.).

## Usage Examples

```bash
# Get help for any command
python main.py scan --help
python main.py defensive --help

# Run a basic footprint scan on a domain and save the output
python main.py scan footprint google.com --output google_footprint.json

# Check your own company's domain for data breaches
python main.py defensive breaches mycompany.com

# Generate a SWOT analysis from a previously saved scan
python main.py scan business "Microsoft" --ticker MSFT -o microsoft.json
python main.py ai swot microsoft.json