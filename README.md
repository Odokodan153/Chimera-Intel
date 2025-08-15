# Chimera Intel 🔱

A modular OSINT platform for comprehensive corporate intelligence and counter-intelligence, powered by an AI analysis core.

## Overview

Chimera Intel is a command-line tool designed to solve a critical business problem: information fragmentation. Inspired by the mythological Chimera—a creature forged from multiple animals—this tool synthesizes disparate data streams into a single, unified, and actionable dossier.

It is built to serve two primary functions:
* **Offensive Intelligence:** To gather a deep understanding of external entities like competitors or potential partners.
* **Defensive Counter-Intelligence:** To allow an organization to see its own digital footprint through the eyes of an attacker and proactively identify weaknesses.

## Features

Chimera Intel is organized into several command groups, each with a suite of features.

### SCAN (Offensive Intelligence)
* `scan footprint`: Gathers WHOIS, DNS, and Subdomain information.
* `scan web`: Analyzes a website's technology stack and traffic estimates.
* `scan business`: Retrieves public financial data, news articles, and patent filings.

### DEFENSIVE (Counter-Intelligence)
* `defensive breaches`: Checks for domain-related email breaches via HIBP.
* `defensive leaks`: Scans GitHub for potential secret leaks.
* `defensive typosquat`: Detects potential phishing domains.
* `defensive surface`: Analyzes public-facing assets using Shodan.
* ...and more.

### ANALYSIS (AI & Historical Core)
* `analysis core sentiment`: Analyzes the sentiment of a news headline or text.
* `analysis core swot`: Automatically generates a SWOT analysis from collected data.
* `analysis diff`: Compares historical scans to detect changes over time.
* `analysis forecast`: Forecasts potential future events based on historical data.
* `analysis strategy`: Generates a high-level strategic profile of a target.

## Setup & Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/chimera-intel.git](https://github.com/your-username/chimera-intel.git)
    cd chimera-intel
    ```

2.  **Set up API Keys:**
    -   Create a `.env` file in the root directory (you can copy `.env.example`).
    -   Open the `.env` file and add your secret API keys from the various services used.

3.  **Install the package:**
    This project uses modern Python packaging. The recommended way to install it is using `pip` in "editable" mode within a virtual environment. This installs the `chimera` command globally within your environment.

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -e .
    ```

## Usage Examples

Once installed, you can run the tool from anywhere using the `chimera` command.

```bash
# Get help for any command
chimera --help
chimera scan --help

# Run a basic footprint scan on a domain and save the output
chimera scan footprint google.com --output google_footprint.json

# Check your own company's domain for data breaches
chimera defensive breaches mycompany.com

# Generate a SWOT analysis from a previously saved scan
chimera scan business "Microsoft" --ticker MSFT -o microsoft.json
chimera analysis core swot microsoft.json

### Data Flow Diagram

The following diagram illustrates the typical data flow for a `scan` command.

```mermaid
graph TD
    graph TD
    subgraph User Interface
        A[User runs 'chimera scan footprint google.com'] --> B{CLI Entrypoint (cli.py)};
        A2[User runs 'chimera defensive vuln your-domain.com'] --> B;
        A3[User runs 'chimera defensive darkweb "leaked data"'] --> B;
    end

    subgraph Core Logic
        B --> C[Footprint Module];
        B --> C2[Vulnerability Module];
        B --> C3[Dark Web Module];

        C --> D{gather_footprint_data()};
        D -- Calls --> E[External APIs (VirusTotal, etc.)];
        D -- Calls --> F[Local Libraries (whois, dnspython)];
        
        C2 -- Depends on --> C;
        C2 -- Scans assets with --> G[Local Tools (Nmap)];
        
        C3 -- Queries via --> H[Tor Proxy & Ahmia Onion Service];

        E --> I[Pydantic Models (schemas.py)];
        F --> I;
        G --> I;
        H --> I;
        I --> J[Aggregated Scan Result];
    end

    subgraph Output & Persistence
        J --> K[Utils (utils.py)];
        K -- Output File? --> L{Save to JSON};
        K -- No Output File --> M[Print to Console];
        J --> N[Database Module (database.py)];
        N --> O[Save to chimera_intel.db];
    end

    subgraph Analysis (Later Stage)
        O --> P[Analysis Modules (strategist.py, differ.py)];
        P --> Q[AI Models / Historical Comparison];
        Q --> R[Final Report/Analysis];
    end