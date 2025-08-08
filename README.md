# Chimera Intel 🔱

A modular OSINT platform for comprehensive corporate intelligence and counter-intelligence, powered by an AI analysis core.

## Features

Chimera Intel is organized into three main modules, accessible via a command-line interface.

###  SCAN (Offensive Intelligence)
- `scan footprint`: Gathers WHOIS, DNS, and Subdomain information.
- `scan web`: Analyzes a website's technology stack and traffic estimates.
- `scan business`: Retrieves public financial data, news articles, and patent filings.

### DEFENSIVE (Counter-Intelligence)
- `defensive breaches`: Checks for domain-related email breaches via HIBP.
- `defensive leaks`: Scans GitHub for potential secret leaks.
- `defensive typosquat`: Detects potential phishing domains with dnstwist.
- `defensive surface`: Analyzes public-facing assets using Shodan.
- `defensive ssllabs`: Performs an in-depth SSL/TLS server test.
- *And more...*

### AI (Analysis Core)
- `ai sentiment`: Analyzes the sentiment of news headlines or text.
- `ai swot`: Automatically generates a SWOT analysis from collected data.
- `ai anomaly`: Detects anomalies in numerical data series.

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
    - Rename the `.env.example` file (you should create this) to `.env`.
    - Open the `.env` file and add your API keys from the various services used (VirusTotal, Shodan, Google AI, etc.).

## Usage Examples

```bash
# Run a basic footprint scan on a domain
python main.py scan footprint google.com

# Check your own domain for data breaches
python main.py defensive breaches mycompany.com

# Generate a SWOT analysis from a previously saved scan
python main.py scan business "Apple Inc." --ticker AAPL -o apple.json
python main.py ai swot apple.json