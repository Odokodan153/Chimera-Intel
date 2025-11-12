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
| Command Group             | Feature Command(s)                   | Description                                                                                                                                                                                                                               |
| ------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Action Governance**     | audit, execute                       | Controls and logs automated actions to meet compliance rules.                                                                                                                                                                             |
| **Active CI**             | monitor, detect                      | Active counter-intelligence operations.                                                                                                                                                                                                   |
| **Active Recon**          | scan-host, scan-range                | Active network reconnaissance.                                                                                                                                                                                                            |
| **Advanced Analytics**    | cluster, correlate                   | Deep data mining, clustering, and correlation.                                                                                                                                                                                            |
| **Advanced Media**        | deepfake-check, authenticate         | Advanced media provenance and analysis.                                                                                                                                                                                                   |
| **AI**                    | run                                  | Autonomous Intelligence Agent Framework.                                                                                                                                                                                                  |
| **AI News**               | latest                               | Fetches the latest AI and tech news.                                                                                                                                                                                                      |
| **Alerts**                | list, subscribe                      | Manages real-time alerts from various feeds.                                                                                                                                                                                              |
| **Analyst Ops**           | eccheck, report                      | Audits the operator's operational security footprint.                                                                                                                                                                                     |
| **Analysis**              | core-swot, temporal, signal          | AI-assisted SWOT, temporal analysis, and strategic signal detection.                                                                                                                                                                      |
| **AppInt**                | static, dynamic                      | Mobile application intelligence and analysis.                                                                                                                                                                                             |
| **ARG**                   | run                                  | Argumentation and Reasoning Graph construction.                                                                                                                                                                                           |
| **ARG Fuse**              | fuse                                 | Fuses multiple ARG sources into a cohesive knowledge base.                                                                                                                                                                                |
| **Audit**                 | log, query                           | Centralized system and intelligence audit log.                                                                                                                                                                                            |
| **Autonomous**            | start-agent, mission                 | Runs complex, multi-stage autonomous missions.                                                                                                                                                                                            |
| **Avint**                 | track-flight, monitor-airspace       | Aviation Intelligence.                                                                                                                                                                                                                    |
| **Behavioral**            | profile, analyze                     | Behavioral profiling and analysis.                                                                                                                                                                                                        |
| **Bioint**                | analyze-face, compare-voices         | Biometric Intelligence (Facial and voice recognition).                                                                                                                                                                                    |
| **Biomintr**              | run                                  | Biometric Measurement and Signature Intelligence.                                                                                                                                                                                         |
| **Blockchain**            | run                                  | General blockchain OSINT and analysis.                                                                                                                                                                                                    |
| **Blockchain Tracer**     | trace-path, cluster-wallets          | Advanced tracing of transactions across blockchains.                                                                                                                                                                                      |
| **Brand Protection**      | monitor, takedown                    | Tracks and acts on brand infringement and scams.                                                                                                                                                                                          |
| **Briefing**              | generate                             | Generates a full, multi-page AI-powered executive intelligence briefing.                                                                                                                                                                  |
| **Business**              | financials, patents                  | Retrieves public financial data, news, and patents.                                                                                                                                                                                       |
| **C-Pint**                | run                                  | Communications Intelligence (COMINT) module.                                                                                                                                                                                              |
| **Channel**               | monitor                              | Monitors various communication channels (Slack, forums).                                                                                                                                                                                  |
| **Chemint**               | search-compound, analyze-formula     | Chemical Intelligence.                                                                                                                                                                                                                    |
| **Chimera Intel (Root)**  | version                              | Shows the current software version.                                                                                                                                                                                                       |
| **Chimera Project**       | init, use, status                    | Initializes a project, sets the active context, and checks status.                                                                                                                                                                        |
| **Chimera Project**       | share                                | Shares a project with another user.                                                                                                                                                                                                       |
| **Chimera Project**       | judicial-hold                        | Places project data under legal hold and archives all current evidence.                                                                                                                                                                   |
| **Chimera Project**       | report, signal                       | Generates a comprehensive dossier and analyzes strategic signals.                                                                                                                                                                         |
| **Chimera Project**       | export-stix, import-stix             | Exports/Imports all intelligence to/from a STIX 2.1 bundle.                                                                                                                                                                               |
| **Cloud**                 | scan, monitor                        | Scans for misconfigured cloud assets (S3 buckets, etc.).                                                                                                                                                                                  |
| **Code Intel**            | analyze, leak-check                  | Gathers and analyzes intelligence from code repositories.                                                                                                                                                                                 |
| **Compint**               | run                                  | Competitive Intelligence analysis.                                                                                                                                                                                                        |
| **Connect**               | virustotal, shodan                   | Integrates with third-party threat intelligence platforms.                                                                                                                                                                                |
| **Corporate Intel**       | run                                  | General corporate intelligence analysis.                                                                                                                                                                                                  |
| **Corporate Records**     | search-filings                       | Searches and analyzes legal/corporate filings.                                                                                                                                                                                            |
| **Covert Agent**          | deploy, report                       | Simulates and manages covert intelligence gathering agents.                                                                                                                                                                               |
| **Covert Financial**      | analyze-flow, trace-fiat             | Tracks and analyzes illicit financial flows (Money Laundering).                                                                                                                                                                           |
| **Covert Ops**            | execute                              | Orchestrates cover and deception operations.                                                                                                                                                                                              |
| **Creative Workflow**     | run                                  | Tools for generating creative intelligence artifacts.                                                                                                                                                                                     |
| **Credibility**           | assess-source, verify-claim          | Assesses the credibility of sources and claims.                                                                                                                                                                                           |
| **Crypto**                | track-wallet, get-transactions       | Cryptocurrency analysis and monitoring.                                                                                                                                                                                                   |
| **Cultural**              | add, populate, list                  | Tools for managing and listing Cultural Intelligence profiles.                                                                                                                                                                            |
| **Cultural Sentiment**    | run                                  | Analyzes geopolitical and cultural sentiment.                                                                                                                                                                                             |
| **Cybint**                | scan-host, scan-url                  | Cybersecurity Intelligence (Port scanning, web analysis).                                                                                                                                                                                 |
| **CyTech Intel**          | run                                  | Cyber Technology Intelligence.                                                                                                                                                                                                            |
| **Darkweb**               | search-tor, monitor-forums           | Searches the dark web and monitors forums via Tor.                                                                                                                                                                                        |
| **Deception**             | detect, uncover-mimicry              | Uncovers hidden corporate networks and mimicry.                                                                                                                                                                                           |
| **Deception Playbook**    | generate-plan                        | Creates tailored deception strategies.                                                                                                                                                                                                    |
| **Deception Suite**       | deploy-lures                         | Manages deployment of defensive deception assets.                                                                                                                                                                                         |
| **Deep OSINT**            | run                                  | Module for deep, automated open-source intelligence gathering.                                                                                                                                                                            |
| **Deep Research**         | run                                  | Orchestrates deep research projects.                                                                                                                                                                                                      |
| **Deep Web**              | analyze                              | Analyzes unindexed deep web content.                                                                                                                                                                                                      |
| **Defensive**             | checks, scan-iac                     | Audits security posture for breaches and checks Infrastructure-as-Code.                                                                                                                                                                   |
| **Disinformation**        | analyze, track-narrative             | Tracks and analyzes disinformation campaigns.                                                                                                                                                                                             |
| **Dissemination**         | report-pdf, publish                  | Intelligence reporting and dissemination tools.                                                                                                                                                                                           |
| **EcoInt**                | market-analysis, economic-indicators | Ecological Intelligence (Environmental risk/trend analysis).                                                                                                                                                                              |
| **Econint**               | market-analysis, economic-indicators | Economic Intelligence (Market and indicator analysis).                                                                                                                                                                                    |
| **Ecosystem**             | run                                  | Maps and analyzes organizational ecosystems and networks.                                                                                                                                                                                 |
| **Elecint**               | analyze-device, track-signal         | Electronic Intelligence.                                                                                                                                                                                                                  |
| **Emulation Lab**         | run                                  | Emulates target environments for safe analysis.                                                                                                                                                                                           |
| **Ensembler**             | run                                  | Combines multiple models/detectors for higher confidence results.                                                                                                                                                                         |
| **Entity Resolver**       | resolve, deduplicate                 | Links ambiguous entities across different data sources.                                                                                                                                                                                   |
| **Financial Signals**     | track-movements                      | Detects strategic financial market signals.                                                                                                                                                                                               |
| **Finintrun**             | run                                  | Financial Intelligence Module.                                                                                                                                                                                                            |
| **Footprint**             | run                                  | Gathers initial network and domain footprint.                                                                                                                                                                                             |
| **Forensic Vault**        | store, retrieve                      | Secure storage and management of forensic evidence.                                                                                                                                                                                       |
| **Forensics**             | static-analysis, parse-mft           | Technical and digital forensics tools.                                                                                                                                                                                                    |
| **Fusion**                | data-fusion                          | Fuses multi-source, multi-modal intelligence data.                                                                                                                                                                                        |
| **Geogeocode**            | geocode, reverse-geocode             | General geolocation and mapping tools.                                                                                                                                                                                                    |
| **Geointrun**             | run                                  | Geospatial Intelligence (Geopolitical risk analysis).                                                                                                                                                                                     |
| **Global Monitor**        | run                                  | Continuous global threat monitoring and alerting.                                                                                                                                                                                         |
| **Governance**            | check-policy, update-policy          | Manages internal policy compliance for intelligence gathering.                                                                                                                                                                            |
| **GRC**                   | run                                  | Governance, Risk, and Compliance toolset.                                                                                                                                                                                                 |
| **Hacker News**           | top                                  | Fetches the top stories from Hacker News.                                                                                                                                                                                                 |
| **Historicals**           | snapshot, compare                    | Analyzes and compares historical snapshots of websites.                                                                                                                                                                                   |
| **Honeypot Detect**       | check                                | Detects and flags potential honeypots.                                                                                                                                                                                                    |
| **Humint**                | search-profiles, monitor-person      | Human Intelligence (Social network searches, person monitoring).                                                                                                                                                                          |
| **Image Forensics**       | run                                  | Image forensics pipeline for manipulation detection.                                                                                                                                                                                      |
| **Imint**                 | analyze-image                        | Imagery Intelligence (EXIF extraction, image analysis).                                                                                                                                                                                   |
| **Imint Ingestion**       | ingest-sat, process-uav              | Ingestion pipeline for satellite and UAV imagery.                                                                                                                                                                                         |
| **Industry**              | run                                  | AI-generated analysis of a specific industry.                                                                                                                                                                                             |
| **Infrastructure**        | run                                  | Infrastructure Intelligence Module.                                                                                                                                                                                                       |
| **Internal**              | run                                  | Access and analyze internal data sources.                                                                                                                                                                                                 |
| **Internal Analytics**    | dashboard, query                     | Internal analytics and performance reporting.                                                                                                                                                                                             |
| **Leadership Profiler**   | run                                  | Profiles leadership and executive sentiment/behavior.                                                                                                                                                                                     |
| **Legint**                | search-dockets, monitor-legislation  | Legal Intelligence (Docket search, legislative tracking).                                                                                                                                                                                 |
| **Logistics**             | run                                  | Logistics Intelligence Module.                                                                                                                                                                                                            |
| **Marint**                | track-vessel, monitor-area           | Maritime Intelligence (Vessel tracking via AIS, area monitoring).                                                                                                                                                                         |
| **Market Demand**         | analyze-trend, forecast-demand       | Analyzes market demand trends.                                                                                                                                                                                                            |
| **Masintrun**             | run                                  | Measurement and Signature Intelligence (MASINT) Module.                                                                                                                                                                                   |
| **Media**                 | reverse-search, transcribe           | Performs reverse image search and audio transcription.                                                                                                                                                                                    |
| **Media Forensics Tools** | extract-metadata, hash-file          | General media forensics utilities.                                                                                                                                                                                                        |
| **Media Hardening**       | watermark, encrypt                   | Tools to harden media (images/videos) against tampering.                                                                                                                                                                                  |
| **Metacognition**         | run                                  | Self-analysis and reasoning about the AI's own findings.                                                                                                                                                                                  |
| **Misuse Playbook**       | run                                  | Executes predefined playbooks to detect misuse of platform findings.                                                                                                                                                                      |
| **Moving Target**         | track, predict                       | Tracks and predicts the movement of mobile targets.                                                                                                                                                                                       |
| **Multi Domain**          | run                                  | Fuses intelligence across multiple security and business domains.                                                                                                                                                                         |
| **Network Scanner**       | scan-host, port-scan                 | Network reconnaissance and port scanning utility.                                                                                                                                                                                         |
| **NLP Insights**          | sentiment, topic-model               | Deep Natural Language Processing insights.                                                                                                                                                                                                |
| **Offensive**             | run                                  | Offensive reconnaissance and exploitation tools.                                                                                                                                                                                          |
| **Open Data**             | query-dataset, download              | Accesses and queries open-source data repositories.                                                                                                                                                                                       |
| **Operational Defense**   | run                                  | Operational defense strategies and tools.                                                                                                                                                                                                 |
| **Opsec**                 | audit-policy, profile-leak           | Operations security analysis.                                                                                                                                                                                                             |
| **OSINT Fusion**          | run                                  | Module specialized in fusing multiple OSINT streams.                                                                                                                                                                                      |
| **OT Intel**              | scan-network, analyze-plc            | Operational Technology Intelligence (SCADA, PLC analysis).                                                                                                                                                                                |
| **Persona Profiler**      | run                                  | Creates detailed, actionable human and corporate persona profiles.                                                                                                                                                                        |
| **Personnel**             | search-email, check-leak             | Finds and validates public employee emails and checks for leaks.                                                                                                                                                                          |
| **Physical**              | run                                  | Physical Intelligence (PHYSINT) Module.                                                                                                                                                                                                   |
| **Pipeline**              | build, test                          | Tools to construct and manage intelligence pipelines.                                                                                                                                                                                     |
| **Plausible Deniability** | run                                  | Tools for obscuring attribution and maintaining operational security.                                                                                                                                                                     |
| **Podcast**               | search, transcribe-feed              | Podcast OSINT and transcription tools.                                                                                                                                                                                                    |
| **Pricing**               | analyze-market                       | Analyzes market pricing strategies and intelligence.                                                                                                                                                                                      |
| **Prodint**               | analyze-product, compare-products    | Product Intelligence (Product analysis and comparison).                                                                                                                                                                                   |
| **Profiles**              | username-check                       | Identifies social media profiles via usernames.                                                                                                                                                                                           |
| **Provenance**            | verify-source, chain-of-custody      | Tools to verify data origin and chain of custody.                                                                                                                                                                                         |
| **Purple Team**           | run                                  | Combines offensive (Red) and defensive (Blue) testing.                                                                                                                                                                                    |
| **Qint**                  | create-survey, analyze-responses     | Quantitative Intelligence (Survey/response analysis).                                                                                                                                                                                     |
| **Recon**                 | run                                  | General reconnaissance module (often alias for deeper scans).                                                                                                                                                                             |
| **Red Team**              | run                                  | Adversarial Simulation and Strategy Validation Engine.                                                                                                                                                                                    |
| **Remediation Advisor**   | advise-vuln, generate-fix            | Provides automated advice for vulnerability remediation.                                                                                                                                                                                  |
| **Reporter**              | generate-report                      | General intelligence report generation tool.                                                                                                                                                                                              |
| **Response**              | mitigate, counter-op                 | Automated incident response and counter-offensive operations.                                                                                                                                                                             |
| **Review**                | human-in-loop                        | Flags findings for human review and validation.                                                                                                                                                                                           |
| **Risk Analyzer**         | run                                  | Holistic risk analysis tool.                                                                                                                                                                                                              |
| **Risk Assessment**       | run                                  | General risk assessment calculation tool.                                                                                                                                                                                                 |
| **RT OSINT**              | stream-data, process-realtime        | Real-Time Open-Source Intelligence processing.                                                                                                                                                                                            |
| **Sales Intel**           | target-lead, analyze-persona         | Generates sales intelligence and lead suggestions.                                                                                                                                                                                        |
| **Sandbox**               | detonate-malware, analyze-file       | Malware analysis and file detonation sandbox.                                                                                                                                                                                             |
| **SCAINT**                | scan-deps, check-sbom                | Software Supply Chain Security (SCAINT).                                                                                                                                                                                                  |
| **Scan (General)**        | run                                  | General scanning module (often an alias for footprint).                                                                                                                                                                                   |
| **SEO**                   | analyze-keyword, competitor-seo      | Search Engine Optimization analysis.                                                                                                                                                                                                      |
| **Sigint**                | scan-wifi, analyze-traffic           | Signals Intelligence (Wi-Fi and network traffic analysis).                                                                                                                                                                                |
| **Social**                | analyze-post, sentiment-score        | Social media content analysis.                                                                                                                                                                                                            |
| **Social History**        | run                                  | Monitors and retrieves historical social media activity.                                                                                                                                                                                  |
| **Social Media Monitor**  | stream, alert                        | Real-time social media monitoring for threats and sentiment.                                                                                                                                                                              |
| **Source Triage**         | evaluate, rank                       | Triages and ranks the reliability of intelligence sources.                                                                                                                                                                                |
| **Spaceint**              | track-satellite, monitor-launch      | Space Intelligence (Satellite tracking and launch monitoring).                                                                                                                                                                            |
| **Strategy**              | generate-profile                     | Generates a high-level AI-powered strategic profile.                                                                                                                                                                                      |
| **Supply Chain**          | analyze-tier, assess-vendor          | Supply chain risk assessment.                                                                                                                                                                                                             |
| **Synthetic Governance**  | audit-policy                         | Audits synthetic media generation against policy rules.                                                                                                                                                                                   |
| **Synthetic Media**       | generate, detect, audit              | Creates new media (images, audio, video) using advanced generative models; identifies and analyzes synthetically generated content for deepfakes; verifies media provenance, watermarks, and cryptographic records in the Forensic Vault. |
| **Synthetic Policy**      | check-use                            | Enforces policies for the ethical use of synthetic media.                                                                                                                                                                                 |
| **Sysint**                | run                                  | Systemic Intelligence (SYSINT) and Cascade Analyzer.                                                                                                                                                                                      |
| **Technical Forensics**   | run                                  | Technical and digital forensics.                                                                                                                                                                                                          |
| **Temporal**              | run                                  | Analyzes historical web snapshots to track identity shifts.                                                                                                                                                                               |
| **The Eye**               | run                                  | A foundational intelligence gathering service (often URL/domain monitoring).                                                                                                                                                              |
| **Threat Actor**          | profile, map-ttp                     | Builds threat actor profiles and maps their TTPs.                                                                                                                                                                                         |
| **TPR**                   | run                                  | Third-Party Risk Management scans.                                                                                                                                                                                                        |
| **Trusted Media**         | verify                               | Verifies the authenticity and trustworthiness of media.                                                                                                                                                                                   |
| **TTP**                   | map-cve                              | Maps CVEs to MITRE ATT&CK TTPs.                                                                                                                                                                                                           |
| **User**                  | login, logout, register, status      | User management and authentication.                                                                                                                                                                                                       |
| **Vector Search**         | query-embed, index-data              | High-speed vector search across indexed intelligence data.                                                                                                                                                                                |
| **Vehicleosint**          | plate, track-vin                     | Vehicle OSINT (License plate/VIN tracking).                                                                                                                                                                                               |
| **Vidint**                | run                                  | Video Intelligence Module.                                                                                                                                                                                                                |
| **VOC**                   | run                                  | Voice of the Customer (VOC) Intelligence.                                                                                                                                                                                                 |
| **Wargaming**             | start-war, simulate-scenario         | Simulates complex adversarial scenarios.                                                                                                                                                                                                  |
| **Weathint**              | get-forecast, analyze-climate        | Weather Intelligence (Forecast/climate data analysis).                                                                                                                                                                                    |
| **Web Scraper**           | scrape-url, crawl                    | Advanced web scraping and data extraction.                                                                                                                                                                                                |
| **Web Visualizer**        | run                                  | Visual tool for displaying web data relationships.                                                                                                                                                                                        |
| **WSA**                   | run                                  | Weak Signal Analyzer (Amplifies low-confidence findings).                                                                                                                                                                                 |
| **Zero Day**              | monitor                              | Tracks and monitors new zero-day threats.                                                                                                                                                                                                 |





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

## 🚀 Deployment

### Secret Management

For production deployments, Chimera Intel is configured to use **HashiCorp Vault** for secure secret management. This is the recommended approach for handling sensitive credentials like API keys and database passwords.

To configure the application to use Vault, you must set the following environment variables:

```bash
export VAULT_ADDR="[https://your-vault-server.com](https://your-vault-server.com)"
export VAULT_TOKEN="your-vault-access-token"
export VAULT_SECRET_PATH="kv/data/chimera-intel" # The path to your secrets in Vault