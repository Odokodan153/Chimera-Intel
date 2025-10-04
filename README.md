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

### ⚠️ Responsible Use & Legal Disclaimer

> **For Educational & Professional Use Only**

Chimera Intel is a powerful OSINT tool intended for educational purposes, ethical security research, and defensive analysis by authorized professionals. It provides a wide range of capabilities for gathering and analyzing publicly available information. By downloading or using this software, you acknowledge and agree to the terms and conditions outlined below.

> **You Are Fully Responsible For Your Actions**

The user assumes all responsibility and liability for any actions taken and for any consequences that may arise from using Chimera Intel. You are strictly prohibited from using this tool for any activity that is illegal, malicious, or intended to cause harm. This includes, but is not limited to, scanning systems you do not have explicit written permission to test, collecting private data in violation of privacy laws (e.g., GDPR, CCPA), or engaging in any form of unauthorized computer access.

> **No Warranty & Limitation of Liability**

This tool is provided "AS IS" without any warranty of any kind, express or implied. The data gathered by Chimera Intel is aggregated from third-party sources and may be inaccurate, incomplete, or outdated. You are responsible for independently verifying all information before taking action. The author and any contributors shall **not be held liable for any damages**, claims, or other liabilities arising from the use, misuse, or inability to use this software.

End-User License Agreement (EULA)

By using Chimera Intel, you agree to this End-User License Agreement (EULA). This EULA is a binding legal agreement between you and the developers of Chimera Intel.

Prohibited Uses: You may not use Chimera Intel for any purpose that is unlawful or prohibited by these terms, conditions, and notices. You may not use the tool in any manner that could damage, disable, overburden, or impair any server, or the network(s) connected to any server, or interfere with any other party's use and enjoyment of any services. You may not attempt to gain unauthorized access to any services, other accounts, computer systems, or networks connected to any server or to any of the services, through hacking, password mining, or any other means.

No Reverse Engineering: You may not reverse engineer, decompile, or disassemble the software, except and only to the extent that such activity is expressly permitted by applicable law notwithstanding this limitation.

Termination: Without prejudice to any other rights, the developers of Chimera Intel may terminate this EULA if you fail to comply with the terms and conditions of this EULA. In such event, you must destroy all copies of the software and all of its component parts.

Governing Law: This EULA will be governed by the laws of the jurisdiction in which the developers of Chimera Intel reside, without regard to its conflict of law principles.

Its command-line interface ensures scriptable workflows, automation of repetitive tasks, and easy integration with other tools or CI/CD pipelines, making it a versatile solution for both small-scale investigations and large enterprise deployments.
## ✨ Key Features

Chimera Intel is organized into a powerful, hierarchical CLI, making it easy to access a wide range of features.
| Command Group | Feature Command         | Description                                                                 |
| ------------- | ----------------------- | --------------------------------------------------------------------------- |
| **Project**   | `init`, `use`, `status` | Manages intelligence projects for organized, long-term tracking.            |
|               | `report`                | Generates a comprehensive PDF dossier for the active project.               |
|               | `signal`                | Analyzes data for unintentional strategic signals (e.g., hiring trends).    |
| **Scan**      | `footprint`             | Gathers WHOIS, DNS, subdomains, and enriches with Threat Intelligence.      |
|               | `web`                   | Analyzes website technology stacks, traffic, and tech stack risk.           |
|               | `business`              | Retrieves public financial data, news, and patents.                         |
|               | `cloud`                 | Scans for misconfigured cloud assets like S3 buckets.                       |
|               | `personnel`             | Finds, validates, and enriches public employee email addresses.             |
|               | `profiles`              | Identifies social media profiles via usernames.                             |
|               | `geo`                   | Retrieves geolocation information for IP addresses.                         |
| **Recon**     | `credentials`           | Searches breach data for compromised credentials.                           |
|               | `assets`                | Discovers digital assets like mobile apps and public datasets.              |
|               | `threat-infra`          | Pivots on malicious indicators to map adversary infrastructure.             |
| **Defensive** | `checks`                | Audits security posture for breaches and code leaks.                        |
|               | `vuln`                  | Scans for CVEs and open ports on discovered assets.                         |
|               | `darkweb`               | Searches the dark web for relevant queries via Tor.                         |
|               | `certs`                 | Monitors new SSL/TLS certificate issuance.                                  |
|               | `scan-iac`              | Checks Infrastructure-as-Code (e.g., Terraform) for security flaws.         |
|               | `scan-secrets`          | Detects leaked secrets in code repositories.                                |
| **Offensive** | `api-discover`          | Finds exposed APIs through active reconnaissance.                           |
|               | `enum-content`          | Enumerates hidden web content (directories, files).                         |
|               | `cloud-takeover`        | Checks for subdomain and cloud service takeovers.                           |
| **Internal**  | `analyze-log`           | Analyzes local logs for incident response.                                  |
|               | `static-analysis`       | Performs malware or code static analysis.                                   |
|               | `parse-mft`             | Parses Master File Tables for forensic insights.                            |
| **Corporate** | `hr-intel`              | Gathers strategic intelligence on hiring trends and employee sentiment.     |
|               | `supplychain`           | Collects trade data and supply chain insights.                              |
|               | `ip-deep`               | Tracks trademarks, patents, and IP activity.                                |
|               | `regulatory`            | Monitors lobbying and regulatory activities.                                |
| **Analysis**  | `core`                  | Performs AI-assisted SWOT analysis and sentiment analysis.                  |
|               | `diff`                  | Detects and interprets changes by comparing historical scans.               |
|               | `forecast`              | Predicts potential future events from historical data.                      |
|               | `strategy`              | Generates a high-level AI-powered strategic profile.                        |
|               | `temporal`              | Analyzes historical web snapshots to track a company's "Shifting Identity". |
|               | `behavioral`            | Builds a corporate "psycho-profile" from public communications.             |
|               | `wsa`                   | Amplifies weak signals into high-confidence events using evidence theory.   |
|               | `deception`             | Uncovers hidden corporate networks and mimicry.                             |
| **Auto**      | `enrich-ioc`            | Automatically enriches Indicators of Compromise.                            |
|               | `enrich-cve`            | Enriches CVE data for vulnerability management.                             |
|               | `threat-model`          | Automates threat modeling based on aggregated scan data.                    |
|               | `ueba`                  | Performs User and Entity Behavior Analytics on log files.                   |
|               | `workflow`              | Executes multi-step automated security workflows from a YAML file.          |
| **Connect**   | `virustotal`            | Integrates with VirusTotal for file and URL analysis.                       |
| **Report**    | `pdf`                   | Generates professional PDF reports from scan data.                          |
|               | `graph`                 | Creates interactive HTML knowledge graphs.                                  |
| **Media**     | `reverse-search`        | Performs a reverse image search to find where an image is used online.      |
|               | `transcribe`            | Transcribes audio files to text using an offline Whisper model.             |
| **AppInt**    | `static`                | Performs static analysis on mobile application (.apk) files.                |
| **Imint**     | `analyze-image`         | Extracts EXIF metadata from image files.                                    |
| **Geoint**    | `run`                   | Analyzes a target's geographic footprint for geopolitical risks.            |
| **CYBINT**    | `scan-host`             | Scans a host for open ports, vulnerabilities, and services.                 |
|               | `scan-url`              | Analyzes a URL for threats, technologies, and metadata.                     |
| **FININT**    | `track-wallet`          | Monitors cryptocurrency wallet activity and balances.                       |
|               | `get-transactions`      | Retrieves transaction history for a given wallet address.                   |
| **HUMINT**    | `search-profiles`       | Searches for individuals across social media and professional networks.     |
|               | `monitor-person`        | Continuously monitors a person's online activity for changes.               |
| **LEGINT**    | `search-dockets`        | Searches court dockets and legal filings.                                   |
|               | `monitor-legislation`   | Tracks changes in laws and regulations.                                     |
| **MARINT**    | `track-vessel`          | Tracks maritime vessels using AIS data.                                     |
|               | `monitor-area`          | Monitors a specific maritime area for vessel activity.                      |
| **PRODINT**   | `analyze-product`       | Gathers information about a product from online sources.                    |
|               | `compare-products`      | Compares features, reviews, and prices of multiple products.                |
| **SIGINT**    | `scan-wifi`             | Scans for nearby Wi-Fi networks and analyzes their security.                |
|               | `analyze-traffic`       | Captures and analyzes network traffic.                                      |
| **BIOINT**    | `analyze-face`          | Performs facial recognition and analysis on images.                         |
|               | `compare-voices`        | Compares voice recordings for speaker identification.                       |
| **CHEMINT**   | `search-compound`       | Searches for information about chemical compounds.                          |
|               | `analyze-formula`       | Analyzes chemical formulas and structures.                                  |
| **AVINT**     | `track-flight`          | Tracks aircraft in real-time.                                               |
|               | `monitor-airspace`      | Monitors a specific airspace for flight activity.                           |
| **ECOINT**    | `market-analysis`       | Analyzes market trends and economic indicators.                             |
|               | `economic-indicators`   | Retrieves key economic indicators for a country or region.                  |
| **ELECINT**   | `analyze-device`        | Gathers information about electronic devices.                               |
|               | `track-signal`          | Tracks and analyzes electronic signals.                                     |
| **QINT**      | `create-survey`         | Creates and distributes surveys and questionnaires.                         |
|               | `analyze-responses`     | Analyzes survey responses to extract insights.                              |
| **SCINT**     | `search-papers`         | Searches for scientific papers and research articles.                       |
|               | `track-research`        | Monitors a specific area of scientific research for new developments.       |
| **SPACEINT**  | `track-satellite`       | Tracks the location and status of satellites.                               |
|               | `monitor-launch`        | Monitors for upcoming satellite launches.                                   |
| **WEATHINT**  | `get-forecast`          | Retrieves weather forecasts for a specific location.                        |
|               | `analyze-climate`       | Analyzes historical climate data.                                           |
| **OTINT**     | `scan-network`          | Scans operational technology (OT) networks for devices and vulnerabilities. |
|               | `analyze-plc`           | Analyzes programmable logic controller (PLC) configurations.                |


---


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

Before running, copy the .env.example file to .env and fill in your API keys.
cp .env.example .env
# Now edit the .env file with your keys
nano .env

# Example: Install the 'footprint' scanning plugin
cd plugins/chimera_footprint
pip install -e .
cd ../..

# Example: Install the 'analysis' plugin suite
cd plugins/chimera_analysis
pip install -e .
cd ../..

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
    subgraph User Interface
        A[User runs 'chimera scan footprint google.com'] --> B{CLI Entrypoint (cli.py)};
    end

    subgraph Core Logic
        B --> C[Footprint Module (footprint.py)];
        C --> D{gather_footprint_data()};
        D -- Calls --> E[External APIs (VirusTotal, etc.)];
        D -- Calls --> F[Local Libraries (whois, dnspython)];
        E --> G[Pydantic Models (schemas.py)];
        F --> G;
        G --> H[Aggregated FootprintResult];
    end

    subgraph Output & Persistence
        H --> I[Utils (utils.py)];
        I -- Output File? --> J{Save to JSON};
        I -- No Output File --> K[Print to Console];
        H --> L[Database Module (database.py)];
        L --> M[Save to chimera_intel.db];
    end

    subgraph Analysis (Later Stage)
        M --> N[Analysis Modules (strategist.py, differ.py)];
        N --> O[AI Models / Historical Comparison];
        O --> P[Final Report/Analysis];
    end