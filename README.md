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

Chimera Intel incorporates cutting-edge Synthetic Media Governance capabilities, supporting both the secure generation of media (using models like GANs and Diffusion Models) and the proactive detection of synthetically generated content (deepfakes). This functionality includes mechanisms for robust watermarking and the use of a dedicated Forensic Vault to ensure and audit media provenance and cryptographic records.

Chimera Intel is ideal for security researchers, OSINT enthusiasts, and IT teams looking to **strengthen their security posture**, **investigate incidents**, or **perform advanced competitive intelligence**.

### ⚠️ Responsible Use & Legal Disclaimer

> **For Educational & Professional Use Only**

Chimera Intel is a powerful OSINT tool intended for educational purposes, ethical security research, and defensive analysis by authorized professionals. It provides a wide range of capabilities for gathering and analyzing publicly available information. By downloading or using this software, you acknowledge and agree to the terms and conditions outlined below.

> **You Are Fully Responsible For Your Actions**

The user assumes all responsibility and liability for any actions taken and for any consequences that may arise from using Chimera Intel. You are strictly prohibited from using this tool for any activity that is illegal, malicious, or intended to cause harm. This includes, but is not limited to, scanning systems you do not have explicit written permission to test, collecting private data in violation of privacy laws (e.g., GDPR, CCPA), or engaging in any form of unauthorized computer access.

> **No Warranty & Limitation of Liability**

This tool is provided "AS IS" without any warranty of any kind, express or implied. The data gathered by Chimera Intel is aggregated from third-party sources and may be inaccurate, incomplete, or outdated. You are responsible for independently verifying all information before taking action. The author and any contributors shall **not be held liable for any damages**, claims, or other liabilities arising from the use, misuse, or inability to use this software.

### ⚠️End-User License Agreement (EULA)

By using Chimera Intel, you agree to this End-User License Agreement (EULA). This EULA is a binding legal agreement between you and the developers of Chimera Intel.

Prohibited Uses: You may not use Chimera Intel for any purpose that is unlawful or prohibited by these terms, conditions, and notices. You may not use the tool in any manner that could damage, disable, overburden, or impair any server, or the network(s) connected to any server, or interfere with any other party's use and enjoyment of any services. You may not attempt to gain unauthorized access to any services, other accounts, computer systems, or networks connected to any server or to any of the services, through hacking, password mining, or any other means.

No Reverse Engineering: You may not reverse engineer, decompile, or disassemble the software, except and only to the extent that such activity is expressly permitted by applicable law notwithstanding this limitation.

Termination: Without prejudice to any other rights, the developers of Chimera Intel may terminate this EULA if you fail to comply with the terms and conditions of this EULA. In such event, you must destroy all copies of the software and all of its component parts.

Governing Law: This EULA will be governed by the laws of the jurisdiction in which the developers of Chimera Intel reside, without regard to its conflict of law principles.

Its command-line interface ensures scriptable workflows, automation of repetitive tasks, and easy integration with other tools or CI/CD pipelines, making it a versatile solution for both small-scale investigations and large enterprise deployments.
## ✨ Key Features

Chimera Intel is organized into a powerful, hierarchical CLI, making it easy to access a wide range of features.
| Command Group | Feature Command(s) | Description |
| --------------------- | ------------------------------------ | ---------------------------------------------------------------------------- |
| **Adversary-Sim** | run-test, list-abilities, get-report | Adversary Simulation engine (MITRE CALDERA integration): run a test simulation against a target PAW with specified TTPs, list available CALDERA abilities, and fetch an aggregated operation report. |
| **Acint**     | add, identify, monitor | Adds a new acoustic signature to the library, identifies an audio file's signature against the library, and monitors audio for anomalies compared to a baseline soundscape. |
| **Active brand protection** | register-domains, deploy-decoy, sinkhole | Finds and registers common typos of your primary domain via Cloudflare, deploys decoy honeypot documents to S3, and redirects malicious domains to a sinkhole IP. |
| **Active recon** | run | Runs the consent-gated active reconnaissance playbook from the CLI. |
| **Ai** | sentiment, swot, anomaly | Runs core AI functions for sentiment analysis, SWOT generation, and anomaly detection. |
| **Aia** | execute-objective | Takes a high-level objective and autonomously manages the full intelligence cycle. |
| **Ainews** | latest | Fetches the latest AI-related news articles from public feeds. |
| **Alerts** | list | Manages and lists all dispatched system alerts. |
| **Alternative-hypothesis** | run | Generates competing hypotheses to challenge primary intelligence findings and mitigate bias. |
| **Analytics** | simulate, track, risk-score, plot-sentiment, influence-mapping, quick-metrics, show | Advanced AI analytics, scenario simulation, risk scoring, and negotiation KPI dashboards. |
| **Appint** | static, deep-metadata, device-intel | Mobile Application Intelligence for static APK analysis, deep metadata extraction, and device scanning. |
| **Arg** | query, ingest_example, find-pattern, find-clusters, temporal-query | Manages the Adversary Research Grid (ARG) global correlation graph. |
| **Arg-fuser** | sync-humint | Fuses data from the HUMINT module into the central Chimera Intelligence Graph. |
| **Attack-path** | simulate | Simulates potential attack paths from an entry point to a target asset. |
| **Attribution** | score-actor | Calculates a quantifiable confidence score for a threat actor attribution. |
| **Audit** | log, verify | Manages and verifies the integrity of the immutable, chained-hash audit log. |
| **Automation** | enrich-ioc, threat-model, ueba, enrich-cve, workflow, prioritize-event, pipeline-list, deception-response-workflow, virustotal, check-feeds, pipeline-run-trigger | High-level automation, data enrichment, threat modeling, and workflow orchestration. |
| **Automation playbook** | list, show | Lists and shows the content of example automation playbooks (workflows). |
| **Autonomous** | optimize-models, analyze-ab-test, detect-drift, backtest, simulate | Manages self-improvement, model optimization, and predictive simulation capabilities. |
| **Avint** | track, drone-monitor | Aviation Intelligence for tracking live flights and monitoring drone activity. |
| **Behavioral** | psych-profile | Analyzes public communications to build psychographic and behavioral profiles. |
| **Bias-audit** | run | Audits a JSON analysis report for potential cognitive bias and collection gaps. |
| **Bioint** | monitor-sequences | Biological Intelligence for monitoring public genetic databases. |
| **Biomint** | analyze-face, compare-voices | Biometric Intelligence for face detection and voice print comparison. |
| **Blockchain** | analyze, contract, token-flow | Blockchain & cryptocurrency OSINT for wallets, smart contracts, and token flows. |
| **Blockchain-tracer** | trace | Traces cryptocurrency transactions and builds a flow-of-funds graph. |
| **Briefing** | generate | Generates a full, multi-page AI-powered intelligence briefing for the active project. |
| **Business** | run | Gathers business intelligence: financials, news, patents, and filings. |
| **Channel-intel** | analyze-mix, find-partners, scrape-ads | Channel & acquisition intelligence tools. |
| **Chemint** | monitor-patents-research, track-precursors, analyze-sds, monitor-chemical-news, lookup | Chemical & materials intelligence tools. |
| **Climate**  | report             | Generates a strategic report on climate-driven geopolitical and supply chain risks for a specific country and resource. |
| **Cft** | track-laundering, track-trade, scan-markets | Covert financial tracking toolkit. |
| **Cloud-osint** | run | Searches for exposed cloud storage assets (S3, Azure, GCP). |
| **Code-intel** | analyze-repo | Analyzes a public Git repository for committer and activity intelligence. |
| **Cognitive-mapping** | run | Builds a cognitive map from public communications of a key individual. |
| **Cognitive-warfare** | deploy-shield, run_scenario | Analyzes narratives, identifies psychological exploits, and runs HUMINT scenarios. |
| **Competitive-analyzer** | run | Generates an AI-powered competitive analysis between two targets. |
| **Comint**    | process-pcap       | Analyzes a PCAP file for communications intelligence (text, audio) and correlates entities to the graph. |

| **Compint** | analyze, attribution, brand-audit, counter-disinfo, secure-evidence | Competitive image intelligence for products, ads, and brand safety. |
| **Complexity-analyzer** | run | Maps system interdependencies and predicts cascading failure points. |
| **Corporate-intel** | leadership-profiler, hr-intel, supplychain, ip-deep, regulatory, sec-filings | Gathers deep corporate intelligence (HR, supply chain, IP, SEC filings). |
| **Corporate-records** | registry, sanctions, pep | Searches company registries, sanctions lists, and PEP lists. |
| **Counter-intel** | infra-check, insider-score, media-track, domain-watch, honey-deploy, legal-template | Defensive counter-intelligence including insider threats and media tracking. |
| **Covert** | run | Manages AI-driven autonomous investigation agents. |
| **Covert-ops** | find-hidden-content, check-takeover | Covert digital ops: API enumeration and subdomain takeover checks. |
| **Cpint** | analyze | Integrated Cyber-Physical Systems intelligence and cascade analysis. |
| **Creative-workflow** | export-psd | Manages master templates and exports signed derivatives. |
| **Credibility** | assess | Assesses the credibility of a web source. |
| **Crypto** | forecast | Provides cryptocurrency market intelligence and forecasting. |
| **Cultint** | analyze | Performs cultural intelligence analysis. |
| **Cultural** | add, populate, list | Tools for managing cultural intelligence profiles. |
| **Cultural-sentiment** | run | Analyzes sentiment of text within a specific cultural context. |
| **Cybint** | attack-surface | Runs comprehensive attack surface analysis and generates AI risk assessment. |
| **CYDEC (Deception)** | emulate-ai-shell, generate-honey-graph, deploy-decoy-document | Emulates an AI-powered honeypot shell, generates & injects honey-graphs of fake personas into the ARG, and creates AI-generated decoy documents with tracking beacons. |
| **Cytech-intel** | emerging-tech, malware-sandbox, vuln-hunter | Cyber & technology intelligence for emerging tech and malware. |
| **Daemon** | start, stop, status | Starts, stops, and checks the status of the Chimera Intel background daemon. |
| **Dark-web** | search | Searches for a query on the dark web via a selected search engine. |
| **Deception** | deploy-honeypot | Active defense through deception and honeypot operations. |
| **Deception-detector** | run | Detects corporate mimicry and hidden networks via asset correlation. |
| **Deep-research** | run | Fuses all-source OSINT into a strategic AI-powered intelligence report. |
| **Deep-web** | search | Searches academic portals, journals, and databases using Google CSE. |
| **Defensive** | breaches, leaks, typosquat, surface, pastebin, ssllabs, mobsf, certs, scan-iac, scan-secrets, source-poisoning-detect, adversary-opsec-score | Defensive counter-intelligence and security scanning module. |
| **Diff** | run | Compares the last two scans of a target to detect changes. |
| **Disinfo** | synthetic-narrative-map, audit | Disinformation and synthetic narrative analysis. |
| **Disseminate** | generate | The automated dissemination & briefing suite. |
| **Ecoint** | epa-violations, ghg-emissions, trade-flow-monitor | Ecological & sustainability intelligence tools. |
| **Economics** | macro, micro | Provides macro and micro economic intelligence. |
| **Ecosystem** | run | Analyzes a company's full business ecosystem (partners, competitors, distributors). |                                                          
| **Education intelligence**    | monitor-publications, track-patents, analyze-curriculum | Monitors specified universities, labs, or academics for new publications, tracks patent filings and tech transfer announcements from key institutions, and analyzes curriculum changes at target institutions to spot emerging technical skills. |
| **Elecint** | campaign-finance, sentiment-drift, trace-source | Electoral and political intelligence tools. |
| **Emulation-lab** | provision, destroy | Threat actor emulation lab for running sandboxed campaigns. |
| **Entity-resolver** | resolve-text | Normalizes entities and extracts relationships from text. |
| **Ethint** | audit, privacy-impact-report, source-trust-model | Ethical governance and compliance engine. |
| **Event-modeling** | run | Reconstructs a sequence of events from raw data. |
| **Finint** | track-insiders, search-trademarks, track-crowdfunding, visualize-flow, detect-patterns, simulate-scenario | Financial intelligence tools for pattern detection and simulation. |
| **Footprint** | run | Gathers digital footprint info (subdomains, IPs, WHOIS, etc.) for a domain. |
| **Forcast** | run, train-breach-model | Analyzes historical data to forecast potential events and trains breach models. |
| **Forensics** | (main), artifact-scan, deepfake-scan, provenance-check, map-narrative, detect-poisoning, face-recognize | Deepfake and media forensics plus disinformation analysis. |
| **Fusion** | run | Multi-modal data fusion (4D analysis) engine. |
| **Geoint** | run, wifi-locate, monitor-events, track-aerial, track-imagery | Geopolitical intelligence analysis and monitoring. |
| **Geo-osint** | run | Retrieves geolocation information for one or more IP addresses. |
| **Geo-strategist** | run | Synthesizes data to create a geographic intelligence report. |
| **Global-monitor** | add | Continuous monitoring for keywords (sanctions, VIPs, etc.). |
| **Gov** | log-consent, request-approval, approve, reject | Manages media governance, approvals, and consent logs. |
| **Goverance** | check, list | Tools for managing action governance, risk policies, and pre-flight checks. |
| **Graph** | query, find-path | Interact with the Chimera Intelligence Graph (Neo4j). |
| **Graph-analyzer** | build, narrate | Builds an entity graph from JSON and generates an AI narrative. |
| **Grapher** | create | Creates an interactive knowledge graph from a saved JSON scan file. |
| **Grc** | timestamp, hold, store, retrieve | Manages Data Custodian (GRC) and the encrypted evidence vault. |
| **Grey-lit** | search | Searches grey literature (reports, white papers, etc.). |
| **Historical-analyzer** | run | Analyzes historical changes to a website using Wayback Machine. |
| **Honeypot-detector** | scan-text, scan-meta | Detects honeypots and collection infrastructure. |
| **Humint** | add-source, add-report, analyze, simulate-social, register-source, get-source, submit-report, map-link, validate-report, find-links, submit-audio-report | Manages human intelligence sources, reports, and simulations. |
| **Imint** | analyze-content, ocr, analyze-satellite, metadata, change-detect | Imagery & visual intelligence analysis. |
| **Ingest** | url, search | Image ingestion pipeline for fetching, processing, and enriching images. |
| **Infrastructure-dependency** | analyze | Public infrastructure & utilities intelligence (power, water, comms). |
| **Insider** | analyze-vpn-logs | Insider threat and counterintelligence analysis (VPN logs). |
| **Internal** | analyze-log, static-analysis, parse-mft, extract-artifacts | Internal analysis, incident response, and forensics tools. |
| **Inta** | correlate-proxies, score-leads | Internal analytics simulation tools for lead scoring. |
| **Influence** | track | Influence and information operations tracking. |
| **Leadership-profiler** | run | Deep-dive OSINT/HUMINT on key executives. |
| **Lead-suggester** | run | Analyzes the active project and suggests next investigative steps. |
| **Legint** | docket-search, arbitration-search, sanctions-screener, lobbying-search, compliance-check | Legal intelligence tools for compliance and litigation. |
| **Malware-sandbox** | analyze | Retrieves a malware sandbox analysis report for a file hash. |
| **Marint** | track-vessel | Maritime & shipping intelligence for live AIS vessel tracking. |
| **Market-demand** | tam, trends, categories | Market & demand intelligence (TAM/SAM/SOM, trends, clustering). |
| **Masint** | rf-pcap, acoustic, thermal | Measurement and signature intelligence tools. |
| **MDM Engine** | run , schedule --cron <cron_str> , candidates <node_type> | Master Data Management engine for continuous entity resolution; manually run a full cycle, schedule periodic runs, or list potential duplicate candidates. |
| **Media** | reverse-search, transcribe | Media analysis tools for reverse image search and audio transcription. |
| **Media-tools** | exif, ela, ffmpeg-metadata, ffmpeg-frames, find-faces, ssim | CLI for advanced media forensics tools. |
| **Medical** | trials, outbreaks, supply-chain | Monitors ClinicalTrials.gov for company R&D pipelines, fetches the latest disease outbreak alerts from WHO, CDC, or ECDC, and tracks medical device recalls via openFDA. |
| **Metacognition** | run-self-analysis | The metacognition and self-improving AI core. |
| **Money Laundering** | refresh-models, analyze-entity, train-models, run-backtest, run-realtime-monitor | AI-powered AML & intelligence platform CLI. |
| **Movint** | track | Moving target intelligence; fuses AVINT, MARINT, and social OSINT. |
| **Multimodal-reasoning** | run | Processes and reasons across different data types simultaneously. |
| **Multi-domain** | correlate | Multi-domain correlation and fusion tools (SIGINT+HUMINT+FININT). |
| **Narrative** | track, map | Tracks evolution and spread of narratives across news and social media. |
| **Negotiation** | add-counterparty, add-market-indicator, train-rl, simulate-llm | Tools for AI-assisted negotiation and training. |
| **Network-scanner** | run | Performs a non-intrusive network scan for open ports and service banners. |
| **Offensive** | api-discover, enum-content, cloud-takeover, wifi-attack-surface, (callback) | Advanced offensive and reconnaissance operations. |
| **OPDEC** | create-profiles, list-profiles, test-scrape | Operational Deception & Plausible Deniability Engine: generates honey-profiles, lists stored profiles, and runs proxied scrapes with chaff and honey-profile headers. |
| **Open-data** | world-bank | Query open-source financial and economic datasets (e.g., World Bank). |
| **Opsec** | run, footprint | Correlates scan data to find OPSEC weaknesses and generate risk reports. |
| **Opsec-admin** | rotate-key, check-session | Manages analyst OPSEC including API key rotation and session checks. |
| **Osint-fusion** | fuse-profiles, fuse-jobs | Fuses scraped OSINT data into the HUMINT network. |
| **Ot-intel** | recon, iot-scan | Operational technology & ICS/SCADA intelligence (Shodan). |
| **Page-monitor** | add | Continuous web page monitoring for change detection. |
| **Personnel-osint** | emails, enrich | Gathers public employee emails and enriches with profiles. |
| **Pestel-analyzer** | run | Generates a PESTEL analysis from aggregated data for a target. |
| **Physical-osint** | locations, map-facility | Gathers and analyzes physical infrastructure information. |
| **Psyint** | plan, execute | (LOW-RISK) Plans an active PSYINT campaign, generating narrative variants, audience lists, and synthetic assets; (HIGH-RISK) Executes a planned PSYINT campaign (simulation), subject to full `action_governance` and `human_review` checks. |
| **Pipeline** | ingest | Data ingestion, storage, and indexing pipeline. |
| **Playbook** | run-deception | Run automated IR playbooks for specific threats. |
| **Podcast** | run | Podcast Intelligence Module. |
| **Polint** | track-portal | Scans a legislative portal for keywords and runs AI impact analysis. |
| **Policy** | add-subject, check, get-risk | Check ethical guardrails and policies for media generation. |
| **Priceint** | add-monitor, detect-promos, check-elasticity | Pricing & promotion intelligence tools. |
| **Privacy-impact-reporter** | run | Generates a privacy impact report by scanning documents for PII. |
| **Profile-analyzer** | twitter | Analyzes a Twitter user's profile and recent tweets. |
| **Project** | init, use, status, share, judicial-hold | Manages intelligence projects (create, load, set active, share, legal hold). |
| **Project-report** | run | Generates an automated, comprehensive project report (PDF dossier). |
| **Provenance** | generate-keys, embed, verify | Embed and verify signed, timestamped provenance in media. |
| **Purple-team** | run-exercise, hunt-ttp, emulate-actor | Run advanced multi-stage Red/Blue/CTI exercises. |
| **Qint** | research, trl-analysis, pqc-status | Quantum intelligence tools (arXiv, TRL analysis, NIST PQC monitoring). |
| **Radint** | analyze-sar | Performs algorithmic change detection on 'before' and 'after' geospatial images (e.g., .tif) within a defined AOI. |
| **Recon** | credentials, assets, threat-infra, passive-dns-query | Reconnaissance module for credentials, assets, and passive DNS. |
| **Red-team** | generate, phishing-simulation, simulate-ttp | Generates red team insights, phishing simulations, and TTP emulation. |
| **Remediation-advisor** | cve, domain, infra, ai-plan | Provides actionable remediation plans for threats. |
| **Response** | add-rule, simulate-event, malware-sandbox | Manages automated incident response rules and actions. |
| **Review** | list, approve, deny | Manages the human review queue for sensitive actions. |
| **Radio Frequency** | BLE, Wi-Fi live, SDR | Scans for nearby Bluetooth devices, performs live Wi-Fi scans for APs and clients, and actively detects RF signals using an SDR. |
| **Risk-analyzer** | run | Generates holistic risk scores by aggregating known intel. |
| **Risk-assessment** | assess-indicator | Assesses risk for an indicator using threat intel and vulnerabilities. |
| **Rt-osint** | monitor | Real-time OSINT monitoring (clearnet feeds, .onion archives) via Tor. |
| **Salint** | find-intent-signals, mine-win-loss | Sales & intent intelligence tools (intent signals, win/loss mining). |
| **Scaint** | analyze-repo | Software supply chain security analysis (SCAINT). |
| **Sentiment-time-series** | run | Tracks sentiment over time and flags significant shifts. |
| **Seo-intel** | run | Analyzes SEO and content strategy against competitors. |
| **Sigint** | monitor-spectrum, live, decode-adsb, decode-ais, decode-ham, fingerprint, model-traffic | Signal intelligence for ADS-B, AIS, HAM radio, and network traffic. |
| **Signal-analyzer** | run | Analyzes a target's public footprint for unintentional strategic signals. |
| **Simulator** | start | Train negotiation skills against AI personas. |
| **Social-analyzer** | run | Finds and analyzes content from a target's RSS feed for strategic topics. |
| **Social-history** | monitor | Tracks historical changes to public social media profiles. |
| **Social-osint** | run, tiktok-profile, tiktok-hashtag | Social media OSINT tools (Sherlock, TikTok scraping). |
| **Source-triage** | run | Run OSINT triage checks (WHOIS, dynamic scrape) on a source URL. |
| **Source-trust-model** | run | Provides a risk-weighted confidence score for an information source. |
| **Strategic-analytics** | kpi-report | Strategic intelligence & KPI reporting integrating other modules. |
| **Strategic-forecaster** | run | AI-powered strategic forecaster & early warning system. |
| **Strategy** | run | Generates an AI-powered strategic profile of a competitor. |
| **Supply-chain-risk** | analyze | Analyzes software dependencies and hardware providers for vulnerabilities. |
| **Sysint** | analyze | Systemic intelligence & cascade analyzer. |
| **Tech-forensics** | lighting, perspective, aberration, eyes, lipsync, all | Run advanced technical forensic analyses (lighting, perspective, lip sync). |
| **Temporal-analyzer** | snapshots | Fetches historical web snapshots to analyze a company's shifting identity. |
| **Threat-actor-intel** | profile | Gathers and synthesizes an intelligence profile for a known threat actor. |
| **Threat-hunter** | run | Hunts for a threat actor's known IOCs in local logs. |
| **Topic-clusterer** | run | Analyzes documents to find and name emerging topic clusters. |
| **Tpr** | run | Runs a comprehensive third-party risk management scan against a target domain. |
| **Traffic** | analyze | Advanced network traffic analysis from PCAP files. |
| **Ttp** | map-cve | Maps CVE vulnerabilities to MITRE ATT&CK techniques. |
| **User** | add, login, logout, status | Manages user accounts and authentication. |
| **Vault** | hash-image, reverse-search, create-receipt, verify-receipt, export-derivative, generate-key | Advanced forensics: image hashing, reverse search, and forensic vault. |
| **Vector-search** | embed, build-index, search | Image similarity search using CLIP embeddings and FAISS. |
| **Vehicle-osint** | search | Looks up a Vehicle Identification Number (VIN) for OSINT. |
| **Vidint** | analyze | Video intelligence operations (frame extraction, motion/object detection). |
| **Voc-intel** | run | Analyzes customer reviews for sentiment, topics, and insights. |
| **Wargaming** | run-supply-chain | Massive scenario & wargaming engine to run 'what-if' scenarios. |
| **Weak-signal-analyzer** | run | Amplifies weak signals from various scans using evidence theory. |
| **Weathint** | get | Performs weather intelligence tasks. |
| **Web-analyzer** | run | Analyzes web-specific data (tech stack, traffic, screenshots) for a domain. |
| **Web-scraper** | parse-article, scrape-dynamic | Active tools for scraping and parsing web data. |
| **Visual-diff** | run | Visually compares web page screenshots from the diff module. |
| **Wifi-analyzer** | analyze | Wireless network analysis from PCAP files. |
| **Voice-match** | adversary-voice-match | Checks audio against a library of known fraudulent or adversary voices. |
| **Zeroday** | monitor | Monitors security feeds for emerging exploits and zero-days. |




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

## Deployment

### Secret Management

For production deployments, Chimera Intel is configured to use **HashiCorp Vault** for secure secret management. This is the recommended approach for handling sensitive credentials like API keys and database passwords.

To configure the application to use Vault, you must set the following environment variables:

```bash
export VAULT_ADDR="[https://your-vault-server.com](https://your-vault-server.com)"
export VAULT_TOKEN="your-vault-access-token"
export VAULT_SECRET_PATH="kv/data/chimera-intel" # The path to your secrets in Vault