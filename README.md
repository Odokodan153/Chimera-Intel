# Chimera Intel 🔱

**A modular OSINT platform for comprehensive corporate intelligence and counter-intelligence, powered by an AI analysis core.**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests Passing](https://img.shields.io/badge/tests-passing-brightgreen)](tests)

---

Chimera Intel is a command-line first OSINT (Open Source Intelligence) tool designed to solve a critical business problem: **information fragmentation**. Inspired by the mythological Chimera—a creature forged from multiple animals—this tool synthesizes disparate data streams into a single, unified, and actionable dossier.

Chimera Intel is a **comprehensive Open Source Intelligence (OSINT) and cybersecurity platform** designed for both **offensive intelligence gathering** and **defensive monitoring**.  
It is a modular, extensible tool that allows cybersecurity professionals, penetration testers, and threat analysts to perform thorough reconnaissance on corporate, organizational, and personal digital footprints.  

By combining multiple specialized modules—ranging from domain footprinting, web and business intelligence, to AI-driven analysis—Chimera Intel enables users to gather actionable insights efficiently.  
It integrates various APIs, local scanning tools, and machine learning models to automate the collection, correlation, and analysis of large datasets, reducing manual effort while maintaining accuracy.  

The platform is designed with **flexibility and modularity** in mind:  
- Offensive modules provide detailed visibility into target infrastructure, public assets, and business-related data.  
- Defensive modules allow organizations to monitor for potential breaches, data leaks, and malicious activity affecting their brand or digital assets.  
- AI modules leverage state-of-the-art machine learning techniques to provide predictive insights, anomaly detection, and strategic recommendations.  

Chimera Intel is ideal for security researchers, OSINT enthusiasts, and IT teams looking to **strengthen their security posture**, **investigate incidents**, or **perform advanced competitive intelligence**.  

Its command-line interface ensures scriptable workflows, automation of repetitive tasks, and easy integration with other tools or CI/CD pipelines, making it a versatile solution for both small-scale investigations and large enterprise deployments.
## ✨ Key Features

Chimera Intel is organized into a powerful, hierarchical CLI, making it easy to access a wide range of features.

| Command Group | Feature Command | Description |
| :--- | :--- | :--- |
| **`scan`** | `footprint` | Gathers WHOIS, DNS, Subdomains, and enriches them with Threat Intelligence from AlienVault OTX. |
| | `web` | Analyzes a website's technology stack (Wappalyzer, BuiltWith) and traffic estimates. |
| | `business` | Retrieves public financial data, news articles, and patent filings. |
| | `cloud s3` | Scans for common S3 bucket misconfigurations for a given keyword. |
| | `personnel emails`| Searches for public employee email addresses for a given domain via Hunter.io. |
| | `profiles` | Finds social media profiles by username using the Sherlock library. |
| **`defensive`**| `checks breaches` | Checks for domain-related email breaches via Have I Been Pwned (HIBP). |
| | `checks leaks` | Scans GitHub for potential secret leaks using a Personal Access Token. |
| | `vuln run` | Scans assets for open ports (`nmap`) and known vulnerabilities (CVEs) via the Vulners API. |
| | `darkweb search`| Searches the dark web for a query via the Ahmia search engine over a Tor proxy. |
| **`analysis`**| `core swot` | Automatically generates a SWOT analysis from collected data using Google's Gemini Pro AI. |
| | `diff run` | Compares the two most recent historical scans to detect changes over time. |
| | `forecast run` | Forecasts potential future events based on historical data changes. |
| | `strategy run` | Generates a high-level, AI-powered strategic profile of a target. |
| **`report`** | `pdf` & `graph` | Generates professional PDF reports or interactive HTML knowledge graphs from scan data. |

---

## 📖 Use Cases & Example Workflows

Here are a few ways you can use Chimera Intel to gain actionable intelligence.

### Workflow 1: Competitor Analysis
Your goal is to build a complete dossier on a competitor, "megacorp.com".

1.  **Initial Footprint**: `chimera scan footprint megacorp.com -o megacorp.json`
2.  **Technology & Business Intel**: `chimera scan web megacorp.com` and `chimera scan business "MegaCorp Inc"`
3.  **Find Key People**: `chimera scan personnel emails megacorp.com`
4.  **Synthesize with AI**: `chimera analysis strategy megacorp.com`
5.  **Generate Report**: `chimera report pdf megacorp.json`

### Workflow 2: Continuous Self-Monitoring
You want to monitor your own company, "mycompany.com", for external threats.

1.  **Check for Breaches**: `chimera defensive checks breaches mycompany.com`
2.  **Look for Leaked Secrets**: `chimera defensive checks leaks "mycompany.com api_key"`
3.  **Discover Attack Surface**: `chimera defensive vuln run mycompany.com`
4.  **Monitor for Changes**: Set up a weekly cron job to run scans and use `chimera analysis diff run mycompany.com footprint` to get alerts on new subdomains.

---

## 🚀 Quick Start

### 1. Prerequisites
* Python 3.9 or higher.
* `git` installed on your system.
* The `nmap` command-line tool (for the vulnerability scanner).
* A running Tor proxy (like the Tor Browser) for dark web searches.

### 2. Installation
It is highly recommended to install the tool within a Python virtual environment.

```bash
# Clone the repository
git clone [https://github.com/your-username/chimera-intel.git](https://github.com/your-username/chimera-intel.git)
cd chimera-intel

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

# Install the project and all dependencies in editable mode
pip install -e .

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