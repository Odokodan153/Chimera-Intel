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



Its command-line interface ensures scriptable workflows, automation of repetitive tasks, and easy integration with other tools or CI/CD pipelines, making it a versatile solution for both small-scale investigations and large enterprise deployments.
## ✨ Key Features

Chimera Intel is organized into a powerful, hierarchical CLI, making it easy to access a wide range of features.

# Command Reference

| Command Group | Feature Command | Description |
| :--- | :--- | :--- |
| **corporate** | `hr-intel` | Gathers strategic intelligence on hiring trends. |
| | `supplychain` | Collects trade data and supply chain insights. |
| | `ip-deep` | Tracks trademarks, patents, and IP activity. |
| | `regulatory` | Monitors lobbying and regulatory activities. |
| **scan** | `footprint` | Gathers WHOIS, DNS, subdomains, and enriches with Threat Intelligence. |
| | `web` | Analyzes website technology stacks and traffic estimates. |
| | `business` | Retrieves public financial data, news, and patents. |
| | `cloud` | Scans for misconfigured cloud assets like S3 buckets. |
| | `personnel` | Finds public employee email addresses. |
| | `profiles` | Identifies social media profiles via usernames. |
| **offensive** | `api-discover` | Finds exposed APIs through active reconnaissance. |
| | `enum-content` | Enumerates hidden web content. |
| | `cloud-takeover` | Checks for subdomain and cloud takeovers. |
| **defensive** | `checks` | Audits security posture for breaches and leaks. |
| | `vuln` | Scans for CVEs and open ports. |
| | `darkweb` | Searches the dark web for relevant queries. |
| | `certs` | Monitors new SSL/TLS certificate issuance. |
| | `scan-iac` | Checks Infrastructure-as-Code for security flaws. |
| | `scan-secrets` | Detects leaked secrets in code repositories. |
| **internal** | `analyze-log` | Analyzes local logs for incident response. |
| | `static-analysis` | Performs malware or code static analysis. |
| | `parse-mft` | Parses Master File Tables for forensic insights. |
| **analysis** | `core` | Performs AI-assisted SWOT analysis and strategic evaluation. |
| | `diff` | Detects changes by comparing historical scans. |
| | `forecast` | Predicts potential future events from historical data. |
| | `strategy` | Generates a high-level AI-powered strategic profile. |
| | `signal` | Detects emerging trends and anomalies. |
| **auto** | `enrich-ioc` | Automatically enriches Indicators of Compromise. |
| | `enrich-cve` | Enriches CVE data for vulnerability management. |
| | `threat-model` | Automates threat modeling processes. |
| | `ueba` | Performs User and Entity Behavior Analytics. |
| | `workflow` | Executes multi-step automated security workflows. |
| **connect** | `virustotal` | Integrates with VirusTotal for file and URL analysis. |
| **report** | `pdf` | Generates professional PDF reports from scan data. |
| | `graph` | Creates interactive HTML knowledge graphs. |


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
        A1[User runs 'chimera corporate hr-intel ...'] --> B{CLI Entrypoint};
        A2[User runs 'chimera offensive enum-content ...'] --> B;
        A3[User runs 'chimera internal analyze-log ...'] --> B;
    end

    subgraph Core Logic Modules
        B --> C1[Corporate Intel];
        B --> C2[Offensive Recon];
        B --> C3[Internal & Forensic];
        B --> C4[Defensive & Proactive];
        B --> C5[AI & Automation];

        C1 -- Queries --> D1[Strategic Data APIs];
        C2 -- Actively Probes --> D2[Target Systems];
        C3 -- Analyzes --> D3[Local Files (Logs, Artifacts)];
        C4 -- Audits & Monitors --> D4[Public Logs & Local Configs];
        C5 -- Synthesizes Data --> D5[AI Models & Workflow Engine];
    end

    subgraph Data Persistence
        C1 & C2 & C3 & C4 --> E[Pydantic Models (schemas.py)];
        E --> F[Database Module (database.py)];
        F --> G[Save to chimera_intel.db];
    end

    subgraph Output & Integration
        E --> H[Utils (utils.py)];
        H -- Output File? --> I{Save to JSON/PDF};
        H -- No Output File --> J[Print to Console];
        C5 -- Can Orchestrate --> K[External Tools (VirusTotal)];
    end