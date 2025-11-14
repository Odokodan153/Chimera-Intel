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
| Command Group | Feature Command | Example CLI Usage                                                | Description                                                       |
| ------------- | --------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Acint**     | `add`             | `acint add -f tank_engine.wav -n T-72_Engine`                    | Add a new acoustic signature to the library.                      |
|               | `identify`        | `acint identify -f unknown_sound.wav -t 0.5`                     | Identify an audio file's signature against the library.           |
|               | `monitor`         | `acint monitor -f city_noise.wav -b normal_city_ambience -t 2.0` | Monitor an audio file for anomalies against a baseline signature. |
| **ActiveRecon** | `run`            | `active_recon run example.com --user-id user123` | Execute the consent-gated active recon playbook for the target domain as a specific user. |
| **Advanced Analytics**     | `simulate`        | `chimera-intel analytics simulate --event "New competitor enters market" --vars '{"market_share": 0.6, "price_point": 100}' --steps 5` | Runs the Predictive Scenario Engine to simulate a corporate, geopolitical, or market event over a specified number of steps, forecasting variable changes and providing a narrative summary.         |
|               | `track`           | `chimera-intel analytics track --topic "AI in healthcare" --data data_sources.txt`                                                     | Runs the Narrative & Influence Tracker, analyzing data sources to detect key narratives, sentiment, influence scores, misinformation alerts, key influencers, and emerging themes for a given topic. |
|               | `risk-score`      | `chimera-intel analytics risk-score --company "DemoCorp" --signals '{"cyber": "High vulnerability detected", "pr": "Positive news"}'`  | Runs the Corporate Risk Scorer to calculate a holistic risk score for a company based on multi-domain signals, providing an overall risk score and a domain-specific breakdown.                      |
| **AdvancedNLP** | `detect-argument-tactics` | `advanced-nlp detect-argument-tactics "Everyone is doing it, so it must be right."` | Analyze a message for argumentation tactics, persuasive techniques, or logical fallacies. Uses AI if API key is available; otherwise falls back to rule-based detection. |
| **Adversary-sim** | `run-test`       | `adversary-sim run-test AGENTPAW123 --ttp T1059.003 --ttp T1548.002` | Executes a test simulation using a stub plan and a target that already has a CALDERA agent paw. |
|                   | `list-abilities` | `adversary-sim list-abilities`                                       | Retrieves all CALDERA abilities from the configured CALDERA server.                             |
|                   | `get-report`     | `adversary-sim get-report 4a91d13d-75b0-4b4c-9f40-bc44d71234ab`      | Fetches the detailed report and executed steps for a specific CALDERA operation ID.             |
| **AI**    | `sentiment`     | `ai-app sentiment "The product launch was a huge success!"` | Analyzes the sentiment of the provided text using a local transformer model.                   |
|               | `swot`          | `ai-app swot ./data/osint_data.json`                        | Generates a SWOT analysis from a JSON OSINT data file using Google Generative AI (Gemini Pro). |
|               | `anomaly`       | `ai-app anomaly "100,110,250,90,105"`                       | Detects anomalies in a numerical dataset using Isolation Forest.     
| **AIA**       | `execute-objective` | `aia execute-objective "Investigate suspicious domain activity" --output report.json --max-runs 3 --timeout 120 --max-runtime 600` | Artificial Intelligence Agent. Takes a high-level natural language objective and autonomously manages the full intelligence cycle, executing tasks, reasoning, and producing a final consolidated report. | 
| **AI News**    | `latest`        | `ainews latest --limit 5` | Fetches the latest AI-related news articles from Ars Technica and displays them in a formatted table. |
| **Alerts**    | `list`          | `alerts list --status new` | Lists all dispatched alerts, optionally filtered by status (`new` or `acknowledged`). |
| **Alternative Hypothesis** | `run`           | `alternative_hypothesis run TARGET_XYZ --output results.json` | Generates competing hypotheses to challenge primary intelligence findings for a given target. |
| **Analyst Operational Security** | `rotate-key`    | `opsec-admin rotate-key analyst_username123 --reason "Key compromised" --admin-user admin` | Generates a new secure API key for an analyst, encrypts it, saves it to their profile, and logs the event. Only shown once; must deliver securely. |
|                 | `check-session` | `opsec-admin check-session analyst_username123 --max-hours 8`                              | Checks if an analyst's session is still valid based on last login time and a maximum allowed duration. Logs if expired.                            |
| **Analytics** | `show`              | `analytics show`                                                                    | Displays a dashboard with KPIs for negotiation performance, including total sessions, successful deals, average duration, and recent sentiment trends. |
|               | `plot-sentiment`    | `analytics plot-sentiment 12345 --output sentiment_plot.png`                        | Retrieves sentiment scores for a negotiation ID and plots them over time. Optionally saves the plot.                                                   |
|               | `influence-mapping` | `analytics influence-mapping ai_safety --geography USA --output influence_map.json` | Maps and scores influence of key entities from the database for a target space and optional geography.                                                 |
|               | `quick-metrics`     | `analytics quick-metrics ProjectX --output quick_metrics.json`                      | Calculates key 'quick win' performance metrics for a specified project, including subdomain discovery, corroboration, MTTC, and false positive rates.  |
| **App Intelligence**    | `static`        | `appint static /path/to/app.apk --output static_results.json`   | Performs static analysis on an Android APK, decompiling it and searching for hardcoded secrets.               |
|               | `deep-metadata` | `appint deep-metadata /path/to/file.dwg --output metadata.json` | Extracts non-standard metadata from niche file types such as CAD files, Shapefiles, OLE documents, or images. |
|               | `device-intel`  | `appint device-intel --output device_info.json`                 | Scans a connected Android device via ADB to collect device metadata and lists of installed and system apps.   |
| **Arg**       | `query`          | `arg query "MATCH (n:Person) RETURN n LIMIT 5"` | Executes a direct, read-only Cypher query against the ARG and displays results in a table.                              |
|               | `ingest_example` | `arg ingest_example`                            | Ingests a small set of example entities and relationships into the ARG for testing or demo.                             |
|               | `find-pattern`   | `arg find-pattern shared_directors`             | Runs a pre-defined automated pattern search, e.g., finding people who are directors of multiple companies.              |
|               | `find-clusters`  | `arg find-clusters`                             | Executes Weakly Connected Components (WCC) clustering using Neo4j GDS to find disjoint subgraphs. Requires GDS library. |
|               | `temporal-query` | `arg temporal-query Company shellco-a.com`      | Retrieves temporal evolution of a specific entity and its relationships, ordered by update time.                        |
| **Arg fuser** | `sync-humint`   | `arg-fuser sync-humint` | Reads all HUMINT data from PostgreSQL and fuses it as nodes and relationships into the Neo4j ARG. |
| **Attack-path** | `simulate`      | `attack-path simulate --entry-point "Public-Facing Web Server" --target-asset "Customer Database"` | Simulates attack paths between two assets using graph data from the database. Identifies shortest valid attack paths if they exist. |
| **Attribution** | `score-actor`   | `attribution score-actor "APT-42" '[{"type": "TTP", "id": "T1059.001", "weight": 0.7}, {"type": "IOC", "value": "1.2.3.4", "weight": 0.5}]' --output results.json` | Calculates a confidence score for a proposed threat actor based on provided indicators and a threat actor DB. Saves or prints the results. |
| **Audit**     | `log`           | `audit log --user "alice" --action "login_attempt" --status "SUCCESS"` | Logs a new action to the immutable audit log, calculating its hash and linking to the previous entry. |
|               | `verify`        | `audit verify`                                                         | Verifies the integrity of the entire audit log chain, detecting any tampering or broken links.        |
| **Auto**      | `enrich-ioc`                  | `chimera auto enrich-ioc 8.8.8.8 bad-domain.com -o results.json`                                     | Enriches Indicators of Compromise (IPs, domains, hashes) with threat intelligence.                        |
|               | `threat-model`                | `chimera auto threat-model example.com -o threats.json`                                              | Generates potential attack paths based on historical scan data for a given domain.                        |
|               | `ueba`                        | `chimera auto ueba user_logs.csv -o anomalies.json`                                                  | Analyzes user activity logs to detect statistical behavioral anomalies.                                   |
|               | `enrich-cve`                  | `chimera auto enrich-cve CVE-2021-44228 CVE-2022-12345 -o cve_info.json`                             | Enriches CVE IDs with details like CVSS scores, summaries, and references.                                |
|               | `workflow`                    | `chimera auto workflow discovery.yaml`                                                               | Executes a predefined YAML workflow of Chimera Intel commands.                                            |
|               | `prioritize-event`            | `chimera auto prioritize-event '{"target": "example.com", "type": "manual"}' -o prioritized.json`    | Runs an event through the Alert Prioritization Engine to rank threats.                                    |
|               | `pipeline-list`               | `chimera auto pipeline-list -o pipelines.json`                                                       | Lists all configured Automation Pipelines (IFTTT workflows).                                              |
|               | `deception-response-workflow` | `chimera auto deception-response-workflow deepfake.mp4 "CEO Name" -t 0.8`                            | Automated response workflow for high-confidence deepfake media, executing legal, PR, and internal alerts. |
|               | `virustotal`                  | `chimera auto virustotal malware_sample.exe -o vt_result.json`                                       | Submits a file to VirusTotal for analysis and retrieves results.                                          |
|               | `check-feeds`                 | `chimera auto check-feeds -o data_quality.json`                                                      | Checks the status, freshness, and schema integrity of external data feeds (OTX, Vulners, VirusTotal).     |
|               | `pipeline-run-trigger`        | `chimera auto pipeline-run-trigger '{"target": "example.com", "event_type": "vulnerability_found"}'` | Executes configured automation pipelines in response to a raw event.                                      |
| **Autonomous** | `optimize-models` | `autonomous optimize-models --module forecaster --performance-data last-90-days --auto-trigger` | Analyze historical performance data for a module and generate a model optimization plan; can auto-trigger retraining. |
|                | `analyze-ab-test` | `autonomous analyze-ab-test --auto-deploy`                                                      | Analyze A/B test results from the database and recommend a winning model variant; optionally deploy automatically.    |
|                | `detect-drift`    | `autonomous detect-drift --baseline baseline.csv --new new.csv --auto-trigger`                  | Detect data drift between two datasets using statistical tests; can trigger retraining if drift is detected.          |
|                | `backtest`        | `autonomous backtest --model forecast_model_v1`                                                 | Perform backtesting of a forecasting model against historical data and calculate accuracy.                            |
|                | `simulate`        | `autonomous simulate --scenario "If company X launches product Y"`                              | Run a predictive “what-if” simulation scenario to evaluate potential risks, opportunities, and outcomes.              |
| **Avint**     | `track`         | `avint track --icao24 abc123 --output live_flights.json`                  | Tracks live flights from the OpenSky Network, optionally filtering by a specific ICAO24 aircraft, with results saved to a JSON file or DB. |
|               | `drone-monitor` | `avint drone-monitor "40.7128,-74.0060" --radius 10 --output drones.json` | Monitors open-source drone activity near a specified latitude/longitude, within a configurable radius, saving results to JSON or DB.       |
| **Behavioral** | `psych-profile` | `behavioral psych-profile "ExampleCorp" --output profile.json` | Analyzes public communications (news, job postings) to generate a psychographic profile of a company, summarizing dominant behavioral traits and narrative entropy. |
| **Bias Audit** | `run`           | `bias-audit run report.json --output bias_results.json` | Audits a JSON analysis report for potential cognitive or collection biases using an LLM, returning structured findings and recommendations. |
| **Bioint**    | `monitor-sequences` | `bioint monitor-sequences --target BRCA1 --email user@example.com --db GenBank` | Continuously scans public genetic sequence databases (currently only GenBank) for specific gene fragments, markers, or sequences. |
| **Biomint**   | `analyze-face`   | `biomint analyze-face sample_image.jpg --output results.json`                            | Detects and locates human faces in an image or video file; can save results to a JSON file.                       |
|               | `compare-voices` | `biomint compare-voices voice1.wav voice2.wav --threshold 0.85 --output comparison.json` | Compares two audio files to determine if the voices match based on a similarity score; outputs results to a file. |
| **Blockchain** | `analyze`       | `blockchain analyze 0xAbC123... --output wallet_analysis.json`            | Analyzes an Ethereum wallet for balance and recent transactions using the Etherscan API.     |
|                | `contract`      | `blockchain contract 0xDeF456... --output contract_analysis.json`         | Analyzes a smart contract for verification status, creator, and token information.           |
|                | `token-flow`    | `blockchain token-flow 0xAbC123... --token USDT --output token_flow.json` | Tracks recent ERC20 token flows (up to 50) for a wallet; optionally filters by token symbol. |
| **Blockchain Tracer**    | `trace`         | `tracer trace 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --chain bitcoin --output tx_graph.html` | Traces transactions for a cryptocurrency address on a specified blockchain and optionally generates an interactive HTML transaction graph. |
| **Brand Protection** | `register_domains` | `abp register_domains -f myproject.com --cf-token $CLOUDFLARE_API_TOKEN --live-run`                                                                              | Register typo domains for a primary domain (live registration). |
|                     | `deploy_decoy`     | `abp deploy_decoy ./decoy.pdf --s3-bucket my-bucket --s3-key decoys/doc.pdf --watermark ABC123 --aws-key $AWS_ACCESS_KEY_ID --aws-secret $AWS_SECRET_ACCESS_KEY` | Deploy a decoy document to S3 with metadata.                    |
|                     | `sinkhole`         | `abp sinkhole bad.myproject.com --sinkhole-ip 10.0.0.1 --cf-token $CLOUDFLARE_API_TOKEN`                                                                         | Redirect traffic from a malicious domain to a sinkhole IP.      |
| **Briefing**  | `generate`      | `briefing generate --template ciso_daily --output briefing.pdf` | Generates a multi-page AI-powered intelligence briefing for the active project using a specified template; can save as PDF or print to console. |
| **Business Intel** | `run`           | `business run --company "Tesla Inc" --ticker TSLA --filings -o tesla.json` | Gathers business intelligence for a target company, including financials (Yahoo Finance), news (GNews API), patents (Google Patents), and optional SEC filings analysis. Results can be saved to a JSON file. |
| **CCI**       | `generate-chaff` | `cci generate-chaff acme.com --count 15`            | Generates background 'chaff' HTTP traffic to mask a real operation. Requires configured proxy.           |
|               | `self-monitor`   | `cci self-monitor --proxy socks5h://127.0.0.1:9050` | Scans clearnet and .onion sites for the platform's own assets. Triggers critical alerts on new mentions. |
| **Channel**   | `analyze-mix`   | `chanint analyze-mix example.com --output traffic_mix.json` | Estimates the paid vs. organic traffic mix for a domain using Similarweb's traffic-sources API. Requires `similarweb_api_key`.                     |
|               | `find-partners` | `chanint find-partners example.com`                         | Hunts for affiliate, partner, review, and coupon pages using Google CSE and outbound link analysis. Requires `google_api_key` and `google_cse_id`. |
|               | `scrape-ads`    | `chanint scrape-ads --query "BrandName" --platform meta`    | Scrapes public ad libraries (Meta, Google, X) for ad creatives using Playwright. Limited to 5 ads per run.                                         |
| **Chemint**   | `monitor-patents-research` | `chemint monitor-patents-research --keywords "graphene catalyst" --start-date 2023-01-01 --end-date 2023-11-01 --limit 5` | Monitors patents and research papers for new chemical and material developments. Searches USPTO and Google Scholar.                        |
|               | `track-precursors`         | `chemint track-precursors --precursors "sulfuric acid,nitric acid" --output precursors.csv`                               | Tracks sale and shipment of chemical precursors from suppliers (Sigma-Aldrich, Fisher Scientific, VWR). Saves results to CSV.              |
|               | `analyze-sds`              | `chemint analyze-sds --sds-url "https://example.com/sds.pdf"`                                                             | Extracts chemical properties and safety information (GHS pictograms, H/P statements) from a Safety Data Sheet (SDS) in PDF, DOCX, or HTML. |
|               | `monitor-chemical-news`    | `chemint monitor-chemical-news --keywords "battery electrolyte" --limit 10`                                               | Monitors latest chemical industry news from multiple sources and displays results in a table.                                              |
|               | `lookup`                   | `chemint lookup --cid 12345 --output compound.json`                                                                       | Retrieves chemical properties from PubChem for a given CID. Can save results to JSON.                                                      |
| **Climate**| `climaint report "Chile" "Lithium"` | Generates a strategic report on climate-driven geopolitical and supply chain risks for a given country and resource. Pulls data from World Bank indicators (political stability, climate vulnerability), UN Comtrade trade flows, and synthesizes it via the Gemini AI client. |
| **Cloud** | `run`           | `cloud-osint run AcmeCorp --output results.json` | Searches for exposed cloud storage assets (S3, Azure, GCP) using a keyword or active project's company name. Results can be saved to a JSON file. |
| **Code Intel** | `analyze-repo`       | `code analyze-repo https://github.com/example/repo.git --output repo_analysis.json`                                 | Clones and analyzes a public Git repository, providing committer statistics and commit keyword analysis.                                                                   |
|                | `github-search`      | `code github-search -k api_key -k password --org ExampleOrg --output github_leaks.json`                             | Searches GitHub code for specific keywords, optionally within an organization, and saves results to a file.                                                                |
|                | `gitlab-search`      | `code gitlab-search -k api_key -k password --group ExampleGroup --output gitlab_leaks.json`                         | Searches GitLab code for specific keywords, optionally within a group, and saves results to a file.                                                                        |
|                | `analyze-repo-leaks` | `code analyze-repo-leaks -k api_key -k password --org ExampleOrg --group ExampleGroup --output-prefix my_scan -w 5` | Searches for code leaks on GitHub/GitLab and analyzes all discovered public repositories in parallel. Saves two files: `<prefix>_leaks.json` and `<prefix>_analysis.json`. |
| **Cognitive Mapping** | `run`           | `cognitive-mapping run "Elon Musk" --output musk_map.json` | Analyzes public communications of a key individual to generate a cognitive map, including decision-making biases, core values, and predictive assessments. |
| **Cognitive Warfare** | `deploy-shield` | `cognitive-warfare deploy-shield --narrative "Energy Crisis" --keywords "oil,gas,renewables"`                       | Analyzes a narrative topic, identifies psychological triggers, and generates a counter-narrative shield.     |
|                       | `run_scenario`  | `cognitive-warfare run_scenario --scenario-type infiltration --target "Competitor Corp" --objective "Gather intel"` | Runs an AI-powered HUMINT scenario against a target, simulating operations like infiltration or elicitation. |
| **Communications**    | `process-pcap`  | `comint process-pcap ./captures/sample.pcap` | Analyze a PCAP file to extract text and audio communications, perform entity and sentiment analysis, identify speakers, and correlate results in a graph for intelligence insights. |
| **Competitive Analyzer** | `run`           | `competitive-analyzer run "CompanyA" "CompanyB"` | Generates an AI-powered side-by-side competitive analysis between two targets using historical OSINT data. |
| **Competitive Image Intelligence**   | `analyze`         | `compint analyze ./images/product.jpg --use-case product -o result.json` | Analyze an image for a specific competitive intelligence use case (product, packaging, ad_creative, event_presence, partner_logos, manufacturing) and optionally save results. |
|               | `attribution`     | `compint attribution ./images/ad.jpg -o attribution.json`                | Perform creative attribution by checking for reused ad creative on the web and internal vector DB.                                                                             |
|               | `brand-audit`     | `compint brand-audit ./images/logo.jpg -o audit.json`                    | Audit an image for brand misuse or potential counterfeits using AI vision and forensic artifact scanning.                                                                      |
|               | `counter-disinfo` | `compint counter-disinfo ./images/suspicious.jpg -o scan.json`           | Scan an image for deepfakes and traces of AI generation to detect counter-disinformation.                                                                                      |
|               | `secure-evidence` | `compint secure-evidence ./images/evidence.jpg --project legal_case_001` | Secure an image in the encrypted evidence vault, generating an auditable chain-of-custody receipt.  
| **Competitor Monitoring**   | `monitor-schedule-add` | `comp-mon monitor-schedule-add --schedule "0 */6 * * *"` | Schedule the competitor leak monitor to run automatically on a cron schedule (e.g., every 6 hours) across all projects.             |
|               | `run-once`             | `comp-mon run-once --project "project_alpha"`            | Run the competitor leak monitor manually a single time for a specified project, checking GitHub, pastebins, and dark web for leaks. |     
| **Complexity Analyzer** | `run`           | `complexity-analyzer run "AcmeCorp" -o risk.json` | Maps system interdependencies for a target, analyzes systemic risks, identifies critical nodes and cascading failure points, and optionally saves results to a file. |                                                                      
| **Connect**   | `messaging-scrapper` | `connect messaging-scrapper "AcmeCorp" -tc durov -dc 123456789012345678 -o results.json` | Scrapes public Telegram channels and Discord servers for mentions of a target keyword. Results are saved to a JSON file and the database. |
| **Corporate-Intel** | `hr-intel`            | `corporate-intel hr-intel example.com -o hr_results.json`         | Analyzes human capital intelligence: hiring trends and employee sentiment. Requires domain for hiring trends and company name for sentiment analysis. |
|                     | `supplychain`         | `corporate-intel supplychain "Acme Corp" -o trade_results.json`   | Investigates a company's supply chain via trade data from ImportGenius API. Requires company name and valid API key.                                  |
|                     | `ip-deep`             | `corporate-intel ip-deep "Acme Corp" -o trademark_results.json`   | Performs deep intellectual property analysis (trademarks) via USPTO API. Requires company name and API key.                                           |
|                     | `regulatory`          | `corporate-intel regulatory "Acme Corp" -o lobbying_results.json` | Analyzes regulatory and lobbying activities using LobbyingData API. Requires company name and API key.                                                |
|                     | `sec-filings`         | `corporate-intel sec-filings AAPL -o sec_results.json`            | Analyzes a company's SEC filings for risk factors using sec-api.io. Requires ticker symbol and API key.                                               |
|                     | `leadership-profiler` | `corporate-intel leadership-profiler ...`                         | Subcommand imported from the leadership_profiler module. Performs deep-dive OSINT/HUMINT on key executives.                                           |
| **Corporate Records** | `registry`      | `corporate-records registry "Acme Corp" -o registry_results.json`  | Searches official company registries via OpenCorporates API. Requires company name and API key.    |
|                       | `sanctions`     | `corporate-records sanctions "John Doe" -o sanctions_results.json` | Screens a name against the OFAC sanctions and watchlists. Requires name input and internet access. |
|                       | `pep`           | `corporate-records pep "Jane Smith" -o pep_results.json`           | Screens a name against a Politically Exposed Persons (PEP) list. Downloads PEP list if not cached. |
| **Counterintelligence** | `infra-check`    | `counter-intel infra-check "asn:AS15169" --apt-list "apt-c2-cobaltstrike,open-rdp" -o results.json`                                   | Checks for threat actor infrastructure in public assets using Shodan.                                |
|                   | `insider-score`  | `counter-intel insider-score "alice@example.com,bob@example.com" --internal -o insider_results.json`                                  | Generates insider risk scores using public data and optional local file system checks.               |
|                   | `media-track`    | `counter-intel media-track "https://example.com/article" -o media_results.json`                                                       | Tracks media spread using OCR/text extraction to create a high-quality fingerprint.                  |
|                   | `domain-watch`   | `counter-intel domain-watch "chimera-intel.com" "Chimera Intel" --official-urls "https://twitter.com/chimera" -o domain_results.json` | Monitors lookalike domains via DNS and brand impersonation on social platforms.                      |
|                   | `honey-deploy`   | `counter-intel honey-deploy "./assets/image.png" "campaign-q4-blog" --port 8080 -o honey_results.json`                                | Deploys a watermarked image locally and starts a tracking server to log access.                      |
|                   | `legal-template` | `counter-intel legal-template "dmca-takedown" -o legal_template.json`                                                                 | Retrieves legal escalation templates for complaints such as DMCA takedowns or impersonation reports. |
| **Covert Intel Agent**    | `run`           | `covert run --target "John Doe" --objective "Map all company affiliations and digital footprint"` | Executes a multi-step autonomous investigation using AI, linking person, company, digital footprint, and narrative analysis. |
| **Covert Financial Tracking**       | `track-laundering` | `cft track-laundering --targets "Alice Corp,Bob Industries"` | Tracks shell companies and analyzes cryptocurrency transactions for the specified entities.      |
|               | `track-trade`      | `cft track-trade --actors "Alice Corp,Bob Industries"`       | Links shipments to suspect actors and analyzes risk of trade-based espionage.                    |
|               | `scan-markets`     | `cft scan-markets --keywords "weapon,exploit"`               | Scans dark web marketplaces for items matching the given keywords and reports relevant listings. |
| **Covert Ops** | `find-hidden-content` | `covert-ops find-hidden-content example.com` | Scans a target domain for hidden endpoints using predefined sensitive paths. Stores discovered URLs and status codes.                              |
|                | `check-takeover`      | `covert-ops check-takeover example.com`      | Checks common subdomains for CNAME records pointing to services known for takeover risks. Flags potential hijack opportunities and stores results. |
| **CPINT**     | `analyze`       | `cpint analyze --project-file cps_project.json` | Models and analyzes a cyber-physical system from JSON project data. Builds a graph of OT assets, locations, signals, and vulnerabilities, identifies critical nodes using betweenness centrality, and predicts potential cascading failure paths. Displays results in tables for critical nodes and failure paths. |
| **Creative Workflow** | `export-psd`    | `creative-workflow export-psd /path/to/master.psd --key /path/to/key.pem --editor user123 --format png --consent-id abc123` | Exports a derivative asset from a PSD, creates a signed manifest, optionally timestamps it, and stores both derivative and manifest in the database. Supports PNG/JPG output and multiple consent IDs. |
| **Credibility** | `assess`        | `credibility assess https://example.com` | Performs an asynchronous credibility assessment of a web URL. Evaluates SSL, domain age, Google Safe Browsing, content clickbait, social media presence, and assigns a score with factors displayed. |
| **Crypto**    | `forecast`      | `crypto forecast --symbol BTC --market USD --days 7` | Fetches historical cryptocurrency data from Alpha Vantage and generates an ARIMA-based price forecast for the specified number of days. Displays results in a rich table. |
| **Cultural**  | `add`           | `cultural add --code US --name "United States" --directness 7 --formality 6 --power 40 --individualism 91 --uncertainty 46` | Adds or updates a cultural profile in the database with Hofstede scores and directness/formality metrics. |
|               | `populate`      | `cultural populate`                                                                                                         | Populates the database with initial example cultural profiles.                                            |
|               | `list`          | `cultural list`                                                                                                             | Lists all cultural profiles stored in the database in a formatted table.                                  |
| **Culture Intelligence**   | `analyze`       | `cultint analyze "Example Company"` | Performs cultural intelligence analysis on a target entity using aggregated social media, news, and employee sentiment data. Outputs a summary of dominant cultural narratives, sentiments, and values. |
| **Cultural-Sentiment** | `run`           | `cultural-sentiment run "Our company values diversity" --country JP --output results.json` | Analyzes sentiment of text within a specific cultural context and optionally saves results to a JSON file. |
| **Cyber Deception**     | `emulate-ai-shell`      | `cydec emulate-ai-shell`                                                                                        | Launches an interactive AI‑powered honeypot shell emulator that mimics a vulnerable Linux server and responds to attacker‑style commands.                            |
|               | `generate-honey-graph`  | `cydec generate-honey-graph --names "Alex Chen,Maria Garcia" --company AcmeCorp`                                | Creates synthetic employee personas and injects them into the Adversary Resolution Graph as honeypot nodes, optionally linking them to an existing company.          |
|               | `deploy-decoy-document` | `cydec deploy-decoy-document "Project_Titan_Strategy_Q4.txt" --prompt "Confidential merger plan" --id titan-q4` | Generates a synthetic “secret” document, writes it to the local honey‑asset directory, applies a tracking ID, and launches a tracking server to log access attempts. |
| **Cyber Intelligence**    | `attack-surface` | `cybint attack-surface example.com --output report.json` | Runs a comprehensive attack surface analysis on a target domain, aggregates data from multiple modules (footprint, vulnerabilities, web security, API discovery), and generates an AI-powered risk assessment. Optionally saves the report to a JSON file. |
| **Cyber Techology Intelligence** | `emerging-tech`   | `cytech-intel emerging-tech --domain AI --topic AlphaFold`                  | Tracks patents, products, and research for a given emerging technology in a specific domain/topic.                                           |
|                  | `malware-sandbox` | `cytech-intel malware-sandbox --indicator 44d88612fea8a8f36de82e1278abb02f` | Fetches a real-time malware analysis report from VirusTotal for a file hash (MD5, SHA1, SHA256) or URL. Requires a valid VirusTotal API key. |
|                  | `vuln-hunter`     | `cytech-intel vuln-hunter --product "Microsoft Exchange"`                   | Tracks recent vulnerability disclosures, exploits, and patches for the specified software product.                                           |
| **Daemon**    | `start`         | `chimera-daemon start`  | Starts the Chimera Intel daemon in the background. Requires an active project with an enabled daemon configuration. |
|               | `stop`          | `chimera-daemon stop`   | Stops the currently running Chimera Intel daemon process.                                                           |
|               | `status`        | `chimera-daemon status` | Checks if the Chimera Intel daemon is running and displays the PID and active project.                              |
| **Dark Web**  | `search`        | `dark-web search "mycompany.com" --engine ahmia --output results.json` | Searches the dark web for a query using the specified search engine (`ahmia` or `darksearch`). Requires Tor to be running. Results can be saved to a JSON file. |
| **Dark Web Monitor** | `add`           | `dark-monitor add --keywords mycompany.com,internal-api --schedule "0 * * * *"` | Schedules a recurring job to monitor dark web sites for specific keywords. Requires the Chimera daemon to be running. |
| **Dashboard** | `export`        | `dashboard export MyTargetProject` | Exports the raw dashboard JSON data for the specified target to the console. |
| **Data Custodian** | `timestamp`     | `data_custodian timestamp MyProject --content "Sensitive data text" --source "http://source.com/data"` | Cryptographically timestamps raw data and creates an auditable receipt associated with a target. |
|                    | `hold`          | `data_custodian hold R-abc123 --reason "Legal Case #123"`                                              | Applies a judicial hold to a data receipt. Use `--release` to release the hold.                  |
| **Data Pipeline**  | `ingest`        | `pipeline ingest https://example.com --dynamic --output result.json` | Submits a URL to the asynchronous ingestion pipeline, scraping, storing, logging, and indexing data. The `--dynamic` flag enables JS-rendered page scraping, and `--output` saves the result to a JSON file. |
| **Data Playbook**  | `run-deception` | `playbook run-deception /path/to/deepfake.mp4 --target "John Doe" --key /path/to/private_key.pem --output report.json` | Executes the full 6-step Deception Incident Response playbook on a suspected deepfake media file, producing a structured report and optional output JSON. |
| **Dark Web Monitor** | `track_content`               | `dark_social_monitor track_content --keywords "security,privacy" --telegram_channels "chan1,chan2" --discord_channels "12345,67890"` | Search Telegram and Discord channels for specified keywords and return content snippets.         |
|                       | `run`                         | `dark_social_monitor run --keywords "malware" --telegram_channels "cybersec_news" --discord_channels "98765"`                        | Wrapper to execute content tracking and return structured results; validates inputs first.       |
| **Deception** | `run`           | `deception run example.com --output results.json` | Detects corporate mimicry and hidden networks by analyzing shared digital assets and footprints. Results can be saved to a JSON file. |
| **Deception Honeypot** | `deploy-honeypot` | `deception deploy-honeypot --type ssh --port 2222` | Deploys a containerized honeypot of the specified type, exposing it on the given host port. |
| **Deep Web**   | `search`        | `deep_web search "quantum computing research" --cse-id YOUR_CSE_ID --limit 10 --output results.json` | Performs a Google Custom Search Engine lookup across academic portals, journals, and databases. |
| **Deep Web Graph Analyzer** | `find_indirect_relationships` | `deep_graph_analyzer find_indirect_relationships --start_node "CompanyA" --end_node "CompanyB" --max_depth 3`                        | Finds all paths between two nodes up to a maximum depth, filtering out direct connections.       |
|                       | `find_all_partnerships`       | `deep_graph_analyzer find_all_partnerships --company_node "CompanyA" --relationship_type "PARTNER_OF" --depth 2`                     | Finds partners and partners-of-partners up to a given depth based on the specified relationship. |
|                       | `run`                         | `deep_graph_analyzer run --task find_indirect_paths --start_node "CompanyA" --end_node "CompanyB" --max_depth 3`                     | Executes a graph analysis task ('find_indirect_paths' or 'find_partners') and returns results.   |
| **Deep Research** | `run`           | `deep_research run "Artificial Intelligence" --output ai_report.json` | Executes a full-spectrum intelligence fusion workflow and generates a structured, AI-powered OSINT report. |
| **Defensive** | `breaches`                | `defensive breaches example.com -o breaches.json`                              | Checks a domain against Have I Been Pwned (HIBP) for data breaches.                   |
|               | `leaks`                   | `defensive leaks "mycompany.com api_key" -o leaks.json`                        | Searches for potential code and secret leaks on GitHub.                               |
|               | `typosquat`               | `defensive typosquat example.com -o typosquat.json`                            | Checks for phishing or look-alike domains using dnstwist.                             |
|               | `surface`                 | `defensive surface 'org:"My Company"' -o surface.json`                         | Analyzes your public attack surface using Shodan.                                     |
|               | `pastebin`                | `defensive pastebin example.com -o pastebin.json`                              | Searches public pastes for keywords or domains using the paste.ee API.                |
|               | `ssllabs`                 | `defensive ssllabs example.com -o ssllabs.json`                                | Performs an SSL/TLS analysis via the SSL Labs API.                                    |
|               | `mobsf`                   | `defensive mobsf --apk-file app.apk -o mobsf.json`                             | Analyzes an Android APK using a local MobSF instance.                                 |
|               | `certs`                   | `defensive certs example.com -o certs.json`                                    | Monitors Certificate Transparency logs for newly issued SSL certificates.             |
|               | `scan-iac`                | `defensive scan-iac ./terraform -o iac_scan.json`                              | Scans Infrastructure as Code files (Terraform, etc.) for security issues using tfsec. |
|               | `scan-secrets`            | `defensive scan-secrets ./src -o secrets.json`                                 | Scans a local directory for hardcoded secrets using gitleaks.                         |
|               | `source-poisoning-detect` | `defensive source-poisoning-detect https://example.com/feed -o poisoning.json` | Evaluates a URL for intentional misinformation or malicious content.                  |
|               | `adversary-opsec-score`   | `defensive adversary-opsec-score APT28 -o opsec_score.json`                    | Calculates the OPSEC score for a known adversary.                                     |
| **Difference**      | `run`           | `diff run footprint --target example.com` | Compares the last two scans for a given module and target, displays a human-readable summary of changes, detects micro-signals, and optionally sends notifications via Slack or Teams. |
| **Disinformation**   | `synthetic-narrative-map` | `disinfo synthetic-narrative-map "climate change"` | Analyzes news and social media to detect AI-generated prose amplifying a specific narrative; results can be saved to a JSON file and are stored in the database.                             |
|               | `audit`                   | `disinfo audit "BrandX"`                           | Passively monitors social, news, and forum data for coordinated disinformation campaigns targeting the specified entity; results can be saved to a JSON file and are stored in the database. |
| **Ecology**    | `epa-violations`     | `ecoint epa-violations "Acme Corp"`    | Looks up Clean Water Act violations from the EPA for a specified company and displays results in a table.                          |
|               | `ghg-emissions`      | `ecoint ghg-emissions "Acme Corp"`     | Fetches asset-level GHG emissions from Climate TRACE for a specified company or asset and displays them in a table.                |
|               | `trade-flow-monitor` | `ecoint trade-flow-monitor 270900 842` | Monitors trade flows for a given commodity (HS code) and country (UN M49 code), detects anomalies, and outputs results in a table. |
| **Economics** | `macro`         | `economics macro US`   | Fetches and displays key macroeconomic indicators (GDP, inflation, unemployment) for a specified country using the World Bank API.         |
|               | `micro`         | `economics micro AAPL` | Fetches and displays key microeconomic indicators (latest stock price, market cap, P/E ratio) for a specified company using Alpha Vantage. |
| **Ecosystem** | `run`           | `ecosystem run "Acme Corp" "acme.com"` | Analyzes a company's business ecosystem by identifying partners, competitors, and distributors; results can be saved to a JSON file and stored in the database. |
| **Education**    | `monitor_publications` | `eduint monitor-publications --target "Geoffrey Hinton" --target "MIT CSAIL"`             | Monitors specified academic figures, labs, or universities for new publications.           |
|               | `track_patents`        | `eduint track-patents --inst "Stanford University" --inst "MIT"`                          | Tracks patent filings and tech transfer announcements from key institutions.               |
|               | `analyze_curriculum`   | `eduint analyze-curriculum --inst "Carnegie Mellon University" --dept "Computer Science"` | Analyzes curriculum changes at a target institution to identify emerging technical skills. |
| **Electoral & Political Intelligence**   | `campaign-finance` | `elecint campaign-finance C00431445`            | Fetches and displays recent campaign donations for a specified FEC committee.                  |
|               | `sentiment-drift`  | `elecint sentiment-drift "#Election2024"`       | Analyzes public sentiment drift for a political keyword or hashtag on Twitter.                 |
|               | `trace-source`     | `elecint trace-source "misinformation keyword"` | Traces the source of a narrative by analyzing retweet networks and identifying key amplifiers. |
| **Entity Resolver** | `resolve-text`  | `entity-resolver resolve-text "Acme Corp" --input data.txt --output results.json` | Analyzes a text file to extract and normalize entities (people or companies) and their relationships using AI. |
| **Ethical Policy**    | `add-subject`   | `policy add-subject --name "John Doe" --sensitivity MINOR --notes "Under 18"`                   | Adds a new subject profile to the policy database, specifying sensitivity and optional notes.             |
|               | `check`         | `policy check --use-case MARKETING --gen-type FULLY_SYNTHETIC_FACE --subject-name "Jane Smith"` | Checks whether a synthetic media generation request is allowed based on the subject profile and use case. |
|               | `get-risk`      | `policy get-risk --use-case FILM_ADVERTISING --subject-name "Public Official"`                  | Determines the risk level (LOW, MEDIUM, HIGH) for a generation request to identify approval thresholds.   |
| **Ethical Intelligence**    | `audit`                 | `ethint audit operation.json --frameworks data_privacy_gdpr rules_of_engagement_default --severity-level HIGH`   | Audits a proposed operation from a JSON file for ethical and legal compliance.                       |
|               | `privacy-impact-report` | `ethint privacy-impact-report --target "Acme Corp" --justification "Security audit" --scan-id 101 --scan-id 102` | Generates an AI-powered Privacy Impact Report (PIR) for a target based on collected scan data.       |
|               | `source-trust-model`    | `ethint source-trust-model "fringe-blog.com" --content "Recent political analysis article" --output report.json` | Assigns a CRAAP-model-based trust score to a data source using AI assessment of content reliability. |
| **Event Mesh** | `start`         | `event-mesh start`                     | Starts the Real-Time Event Mesh service, monitoring all configured feeds and forwarding events to the CorrelationEngine. |
|               | `feeds`         | `event-mesh feeds --output feeds.json` | Lists all configured real-time feeds from `config.yaml`, optionally saving the output to a JSON file.                    |
| **Event Modeling** | `run`           | `event-modeling run --input ./raw_reports --output timeline.json` | Reconstructs a chronological sequence of events from raw data text files, generating a structured timeline. |
| **Evidencs Vault**       | `store`         | `grc store --target "ProjectX" --source "email-report-123" --content "Sensitive intelligence data"` | Encrypts and stores sensitive data in the Evidence Vault, generating a data receipt for provenance.    |
|               | `retrieve`      | `grc retrieve 7f3c2a1b-4d5e-6f7a-8b9c-0d1e2f3a4b5c --reason "Audit request"`                        | Retrieves and decrypts data from the Evidence Vault, logging the access event in the chain of custody. |
| **Financials** | `analyze-docs`           | `financials analyze-docs --file financial_documents.json`                                      | Extract NLP signals (sentiment, topics, risk factors, entities) from unstructured financial documents.          |
|                | `match-trades`           | `financials match-trades --shipping shipping_records.json --invoices invoices.json`            | Match shipping and logistics records against financial invoices, highlighting discrepancies or partial matches. |
|                | `find-funding-anomalies` | `financials find-funding-anomalies --file funding_events.json --z-score 3.0`                   | Identify unusual funding activity or emerging backers using statistical Z-score analysis.                       |
|                | `correlate-flows`        | `financials correlate-flows --transactions transactions.json --entity-map entity_mapping.json` | Correlate payment flows across corporate accounts, crypto wallets, and shell entities using graph analysis.     |
| **Financial Intelligence**    | `track-insiders`     | `finint track-insiders --stock-symbol AAPL --output insider_data.json`                                                                | Tracks insider trading activity for a specified company stock symbol and optionally saves results. |
|               | `search-trademarks`  | `finint search-trademarks --keyword "TechGadget" --owner "Acme Corp" --output trademarks.json`                                        | Searches patent/trademark databases for keywords or company owners, saving results if requested.   |
|               | `track-crowdfunding` | `finint track-crowdfunding "smartwatch" --output crowdfunding.json`                                                                   | Analyzes crowdfunding platforms for projects matching a keyword, optionally saving results.        |
|               | `visualize-flow`     | `finint visualize-flow "TargetCompany" --transactions-file transactions.json --output graph.html --highlight Suspicious1 Suspicious2` | Builds a money flow network graph from a transactions file, highlighting specified nodes.          |
|               | `detect-patterns`    | `finint detect-patterns "TargetCompany" --transactions-file transactions.json --output aml_patterns.json`                             | Uses AI to detect money laundering patterns from a transaction file and optionally saves results.  |
|               | `simulate-scenario`  | `finint simulate-scenario --node Account123 --scenario sanction --transactions-file transactions.json --target TargetCompany`         | Runs a “what-if” scenario simulation (e.g., sanctions) on a transaction network.                   |
| **Forecast**  | `run`                | `forecast run business_intel TargetCompany` | Analyzes historical scan data for a target to forecast potential future events and detect predictive signals, including ARG-based strategic patterns. |
|               | `train-breach-model` | `forecast train-breach-model`               | Trains a machine learning model to predict data breaches from historical scan data and saves it as `breach_model.pkl`.                                |
| **Forensic Vault**     | `hash-image`        | `vault hash-image /path/to/image.png --output result.json`                                                                                   | Calculate perceptual (pHash) and difference (dHash) hashes of an image for similarity analysis.        |
|               | `reverse-search`    | `vault reverse-search /path/to/image.png -o search_result.json`                                                                              | Perform reverse image search using Google Vision API to find sources and similar images on the web.    |
|               | `create-receipt`    | `vault create-receipt /path/to/evidence.png --key private.pem --tsa-url http://timestamp.digicert.com -o receipt.json`                       | Create a signed and timestamped forensic vault receipt for a file.                                     |
|               | `verify-receipt`    | `vault verify-receipt /path/to/receipt.json --key public.pub.pem --file /path/to/evidence.png`                                               | Verify the integrity and authenticity of a file against its forensic receipt.                          |
|               | `export-derivative` | `vault export-derivative /path/to/master.psd --key private.pem --format jpg --output derivative.jpg --tsa-url http://timestamp.digicert.com` | Export a derivative image (JPG/PNG), calculate hashes, and create a new forensic receipt for it.       |
|               | `generate-key`      | `vault generate-key --output my_key`                                                                                                         | Generate a new RSA keypair for signing; produces `my_key.pem` (private) and `my_key.pub.pem` (public). |
| **Fusion**    | `run`           | `fusion run "John Doe"` | Executes the full 4D Fusion Analysis pipeline on a target identifier (name, username, IP, etc.). It performs entity resolution, pattern-of-life construction, and predictive/cognitive modeling. |
| **Geo OSINT**  | `run`           | `geo-osint run 8.8.8.8 1.1.1.1 --output results.json --map ip_map.html` | Gather geolocation intelligence for one or more IP addresses, save results to JSON, and optionally generate an HTML map. |
| **Geo Strategist** | `run`           | `geo-strategist run "Acme Corp" --output report.json` | Synthesizes multi-source intelligence to produce a Geo-Strategic report, detailing operational centers, hiring locations, and supply chain hubs for the target. |
| **Global Monitor** | `add`           | `global-monitor add --keyword "OFAC" --target "Acme Corp" --schedule "0 */6 * * *"` | Schedules a recurring monitoring job to search Google for a specified keyword related to a target. Alerts are sent when new mentions are detected. |
| **Governance** | `check`           | `gov check red-team:generate AcmeCorp --consent signed_consent.json` | Check if a specific action is allowed for a target, performing all pre-flight checks. |
|                | `list`            | `gov list`                                                           | Display all registered actions and their risk levels.                                 |
| **Graph**     | `build`         | `graph build data.json --output my_graph.html` | Builds and saves an entity relationship graph from a JSON file. The output can be saved to a specified HTML file; if not specified, a default filename is generated. Handles file not found and invalid JSON errors. |
|               | `narrate`       | `graph narrate AcmeCorp`                       | Generates an AI-powered narrative from a target's entity graph. Requires a Google API key; will fail if the key is missing.                                                                                          |
|               | `query`         | `graph query "MATCH (n) RETURN n LIMIT 5"`                      | Executes a raw Cypher query against the graph database and prints the results in a formatted table. Handles query execution errors gracefully.                |
|               | `find-path`     | `graph find-path --from "Domain:example.com" --to "IP:1.2.3.4"` | Finds the shortest path between two nodes in the graph. Node identifiers must follow the format `Label:Name`. Displays the path with nodes and relationships. |
| **Graph_3d**  | `create-3d`     | `graph_3d create-3d scan_results.json --output my_graph.html` | Generates an interactive 3D knowledge graph from a JSON scan result. Saves as an HTML file. If `--output` is not provided, a default filename based on the target is used. |
| **Graph Knowledge**     | `create`        | `graph create scan_results.json --output my_graph.html` | Generates an interactive HTML knowledge graph from a JSON scan result. Nodes include the main target, subdomains, IP addresses, and technologies. Physics and layout options are applied from configuration. |
| **Grey Literature**  | `search`        | `grey-lit search "supply chain risk" --filetype pdf pptx --domain org gov edu --output results.json` | Searches for grey literature (reports, white papers, etc.) using Google Custom Search API. Allows filtering by file type and domain. Results can be printed or saved to a JSON file. |
| **Hacker News**    | `top`           | `hacker top --limit 15` | Retrieves and displays the top stories from Hacker News. Uses the official Firebase API and prints results in a formatted table. |
| **Historical Analyzer** | `run`           | `historical-analyzer run example.com --from 20200101000000 --to 20230101000000` | Analyzes changes between two historical snapshots of a website. Fetches content from the Wayback Machine, generates a diff, and produces an optional AI summary. |
| **Holistic risk analyzer** | `run`           | `risk-analyzer run AcmeCorp --output acme_risk.json` | Generates a full multi-domain risk assessment for a target entity using aggregated intel (financial, legal/regulatory, operational, reputation, HR). Produces a weighted score and risk level, plus a structured component breakdown. |
| **Honeypot**  | `scan-text`     | `honeypot scan-text --text "Check http://canarytokens.com and 192.0.2.1"` | Scans raw text for honeypot signals, including tracking pixels, known honeypot URLs, and known honeypot IPs. Uses regex-based extraction and internal threat lists.            |
|               | `scan-meta`     | `honeypot scan-meta --file-path ./document.pdf`                           | Extracts and scans file metadata for honeypot indicator URLs or domain references. Current implementation uses simulated metadata but the scanning logic is fully implemented. |
| **Human Review**    | `list`          | `review list`                             | Displays all actions currently waiting for human review. Reads the queue file and prints pending items.   |
|               | `approve`       | `review approve abc123 --user supervisor` | Marks a pending review request as approved. Updates the queue entry with reviewer identity and timestamp. |
|               | `deny`          | `review deny abc123 --user supervisor`    | Marks a pending review request as denied. Updates the queue entry with reviewer identity and timestamp.   |
| **Humint**    | `add-source`          | `humint add-source --name "AgentX" --reliability A1 --expertise "Counterintelligence"`                                                   | Adds a new HUMINT source to the database (basic version).                                                    |
|               | `add-report`          | `humint add-report --source "AgentX" --content "Observed unusual activity near facility."`                                               | Adds a new HUMINT report linked to a source (basic version).                                                 |
|               | `analyze`             | `humint analyze "financial irregularities"`                                                                                              | Uses AI to analyze all HUMINT reports related to a specific topic.                                           |
|               | `simulate-social`     | `humint simulate-social --target "Corporate executive with access to internal data" --goal "Elicit project timelines"`                   | Runs a virtual HUMINT simulation of a social interaction.                                                    |
|               | `register-source`     | `humint register-source --name "AgentY" --contact "+123456789" --expertise "Signals" --reliability C3 --consent "Signed"`                | Registers a new HUMINT source with PII encryption and consent tracking.                                      |
|               | `get-source`          | `humint get-source AgentY`                                                                                                               | Retrieves HUMINT source details, redacting PII based on the user's role.                                     |
|               | `submit-report`       | `humint submit-report --source "AgentY" --type "Interview" --content "Report content here" --entity "KeyPerson" --tag "field"`           | Submits a structured field report with automatic entity extraction and forensic vault logging.               |
|               | `map-link`            | `humint map-link --from "AgentY" --rel "Worked with" --to "TargetA" --report-id 101`                                                     | Manually maps a human-network relationship between two entities.                                             |
|               | `validate-report`     | `humint validate-report 101 --status "Confirmed" --comments "Verified by cross-check" --analyst "AnalystA" --update-reliability B2`      | Logs a validation check for a report and optionally updates the source's reliability.                        |
|               | `find-links`          | `humint find-links "AgentY"`                                                                                                             | Finds and displays all 1st-degree network links for a given entity.                                          |
|               | `submit-audio-report` | `humint submit-audio-report --source "AgentY" --file "/path/to/audio.wav" --type "Audio Debrief" --entity "KeyPerson" --tag "interview"` | Transcribes an audio file and submits it as a field report with auto entity extraction and forensic logging. |
| **Image Pipeline** | `run`           | `image-pipeline run sample_image.jpg --output report.json` | Executes the full forensic pipeline on a single image or video, performing acquisition, triage, similarity search, manipulation detection, and generating a forensics report. |
| **Image Playbook**  | `trigger_image_misuse_playbook`  | `trigger_image_misuse_playbook("https://example.com/image.jpg", 0.95)` | Starts the pre-approval workflow for an image misuse event, capturing evidence, generating a forensic report, and creating a human legal review task.      |
|               | `trigger_takedown_from_approval` | `trigger_takedown_from_approval("review_task_id_12345")`               | Executes the post-approval workflow after legal approval, performing takedown requests, notifying comms, updating the graph DB, and monitoring follow-ups. |
| **Imint**     | `analyze-content`   | `imint analyze-content image.jpg --feature ocr`                                                      | Analyze the content of an image using AI vision for features like OCR, objects, logos, location, body-language, or events. Requires GOOGLE_API_KEY.   |
|               | `ocr`               | `imint ocr image.jpg`                                                                                | Extract text from an image using local Tesseract OCR. Offline alternative to `analyze-content --feature ocr`. Requires pytesseract installed.         |
|               | `analyze-satellite` | `imint analyze-satellite --coords 40.7128,-74.0060 --feature object-detection --image satellite.png` | Analyze satellite imagery for a given location. Supports object detection from a local image. Image path required for object-detection feature.       |
|               | `metadata`          | `imint metadata image.jpg --output results.json`                                                     | Extract and analyze EXIF metadata from an image. Optionally saves results to a JSON file.                                                             |
|               | `change-detect`     | `imint change-detect before.jpg after.jpg --output diff.jpg`                                         | Compare two images to detect changes (e.g., satellite photos). Outputs a status, difference score, and optional annotated image highlighting changes. |
| **IMINT Ingestion** | `url`           | `python ingest.py url "https://example.com/image.jpg" -s google_images -c "https://example.com/page"` | Ingests a single image from a direct URL. Fetches the image, normalizes it, calculates hashes and embeddings, enriches (OCR, faces, logos), stores it in S3, links to ARG, and logs metadata in PostgreSQL.                   |
|                     | `search`        | `python ingest.py search "brand logo" -s google_images -n 5`                                          | Searches a data source (Google Images, Twitter) for images matching a query, then ingests each result through the full IMINT pipeline. Handles multiple images and timestamps, storing them with full enrichment and linking. |
| **Industry Intellgence** | `run`                | `industry-intel run "water dispenser" --country USA --output results.json`                  | Gathers and analyzes AI-powered intelligence on a specific industry, globally or for a specific country. Requires GNews and Google API keys. |
|                   | `monopoly`           | `industry-intel monopoly "CompanyX" "water dispenser" --country USA --output monopoly.json` | Analyzes if a company is a monopoly in a specific industry. Uses news and AI analysis. Requires GNews and Google API keys.                   |
|                   | `stability-forecast` | `industry-intel stability-forecast USA --region California --output stability.json`         | Generates a political, economic, and social stability forecast for a country or region. Multi-modal AI analysis.                             |
|                   | `patent-rd`          | `industry-intel patent-rd graphene --company "TechCorp" --output patents.json`              | Monitors new patents, publications, and R&D activity for a topic or company. AI analysis based on news and publications.                     |
|                   | `market-intel`       | `industry-intel market-intel "iPhone 15" smartphone --country USA --output market.json`     | Gathers market intelligence on a product and industry, including pricing trends and competitor activity.                                     |
|                   | `esg-monitor`        | `industry-intel esg-monitor "CompanyX" --industry "energy" --output esg.json`               | Monitors ESG (Environmental, Social, Governance) and sustainability risks for a company using AI analysis.                                   |
| **Infrastructure Intelligence** | `analyze`       | `infrastructure-dependency analyze "1600 Pennsylvania Avenue, Washington, DC" -r 5000 -l 25000` | Analyzes dependencies on critical infrastructure for a given address, including power, water, cell towers, ports, and airports. |
| **Internal Analytics (INTA)** | `correlate-proxies` | `inta correlate-proxies example.com -o proxies.json` | Analyzes stored traffic, UTM/affiliate, and app review data to simulate channel conversion proxies.    |
|                               | `score-leads`       | `inta score-leads example.com -o lead_score.json`    | Uses AI to generate a qualitative lead scoring summary from all collected intent and activity signals. |
| **Internal**  | `analyze-log`       | `internal_app analyze-log /var/log/auth.log --output results.json`                                | Analyze a log file to extract and flag suspicious events.              |
|               | `static-analysis`   | `internal_app static-analysis suspicious.exe --output static_results.json`                        | Perform basic static analysis on a file, including hashes and strings. |
|               | `parse-mft`         | `internal_app parse-mft /mnt/disk/$MFT --output mft_results.json`                                 | Parse a Master File Table ($MFT) to create a file activity timeline.   |
|               | `extract-artifacts` | `internal_app extract-artifacts disk_image.E01 --extract-dir ./artifacts --output artifacts.json` | Extract digital artifacts (Prefetch, ShimCache) from a disk image.     |
| **Influence** | `track`         | `influence track --narrative "Election misinformation"` | Track a narrative across news, Twitter, and Reddit to identify coordinated influence operations. |
| **IoT Device Scanner**  | `discover_devices`            | `iot_device_scanner discover_devices --query 'product:"webcam"'`                                                                     | Search Shodan for exposed IoT devices matching the query string and return device details.       |
|                       | `run`                         | `iot_device_scanner run --query 'org:"Example Corp"'`                                                                                | Wrapper to execute IoT device discovery and return structured results; requires Shodan API key.  |
| **Lead Suggester** | `run`           | `lead_suggester_app run --no-rich` | Analyze the active project and generate AI-powered next-step suggestions for intelligence leads. |
| **Leadership Profiler** | `run`           | `leadership-profiler run --person "Jane Doe" --company "Acme Corp" --output results.json` | Perform a deep-dive OSINT/HUMINT profile on a key executive to identify vulnerabilities, undisclosed affiliations, and insider threat indicators. |
| **Legint**    | `docket-search`        | `legint docket-search --company-name "Acme Corp" --output acme_dockets.json`                             | Searches court records for dockets related to a company.                                            |
|               | `arbitration-search`   | `legint arbitration-search --entity-name "Acme Corp" -o acme_arbitration.json`                           | Searches public web sources for arbitration cases and legal disputes involving the entity.          |
|               | `sanctions-screener`   | `legint sanctions-screener --entity-name "Acme Corp" --ubo --export-controls -o acme_sanctions.json`     | Screens an entity and optionally its UBOs against international sanctions and export control lists. |
|               | `lobbying-search`      | `legint lobbying-search --entity-name "Acme Corp" -o acme_lobbying.json`                                 | Searches for political donations and lobbying expenditures related to the entity.                   |
|               | `compliance-check`     | `legint compliance-check 123 --framework GDPR --framework CCPA --output compliance_report.json --redact` | Filters a stored scan result for PII and compliance issues, optionally redacting data in place.     |
|               | `monitor-schedule-add` | `legint monitor-schedule-add --schedule "0 9 * * 1-5"`                                                   | Schedules the legal monitor to run periodically on a cron schedule, alerting on new court dockets.  |
| **Logistics** | `track`                | `logistics track 1Z9999999999999999 --carrier FedEx`                              | Tracks a shipment by its tracking code and carrier, showing current status and detailed updates.        |
|               | `get-vessel-position`  | `logistics get-vessel-position  IMO1234567 -o vessel_position.json`               | Retrieves live AIS position for a vessel by IMO number using the free AISHUB API.                       |
|               | `find-manifests`       | `logistics find-manifests "Acme Corp" -o acme_manifests.json`                     | Searches for shipping manifests (Bills of Lading) for a target company. Requires a paid trade data API. |
|               | `analyze-supply-chain` | `logistics analyze-supply-chain "Acme Corp" -o supply_chain_report.json`          | Analyzes a target’s supply chain for anomalies such as high-risk ports, based on trade manifest data.   |
|               | `correlate-payment`    | `logistics correlate-payment -p SWIFT12345 -t BL98765 -o correlation_report.json` | Correlates a payment with a trade document (e.g., Bill of Lading) using the MLINT module.               |
| **Malware Sandbox** | `analyze`       | `sandbox analyze 3a7d5f2e... -o sandbox_report.json` | Retrieves a malware sandbox report for a given SHA256 hash. Saves results to a file or prints to console. |
| **Marint**    | `track_vessel`  | `marint track-vessel 9384612 --test` | Tracks a vessel by its IMO number using a live AIS data stream. `--test` runs a single update. |
| **Market Demand** | `tam`           | `market_demand tam "Cloud Computing" "IaaS" --country "USA" --output results.json` | Estimates TAM/SAM/SOM for a given industry and product category using public data and AI synthesis.   |
|                   | `trends`        | `market_demand trends "AI" "ML" --geo US --output trends.json`                     | Tracks demand trends for specified keywords using Google Trends, news analysis, and topic clustering. |
|                   | `categories`    | `market_demand categories "CRM Software" --output categories.json`                 | Discovers and clusters product, feature, or use case categories for a specified topic.                |
| **Master Data Management** | `run-test`       | `adversary-sim run-test ABC123 --ttp T1059.003 --ttp T1071.001` | Runs a test adversary simulation against a specified CALDERA agent using given TTPs.               |
|                   | `list-abilities` | `adversary-sim list-abilities`                                  | Lists all available CALDERA abilities with their IDs, TTPs, and brief descriptions.                |
|                   | `get-report`     | `adversary-sim get-report 7f3b2c1d-...`                         | Fetches the full operation report for a specific CALDERA operation ID and displays parsed results. |
| **Media**     | `reverse-search` | `media reverse-search /path/to/image.jpg --output results.json` | Performs a reverse image search to find where the image appears online using Google Images. |
|               | `transcribe`     | `media transcribe /path/to/audio.wav --output transcript.json`  | Transcribes an audio file to text using an offline speech recognition model (Whisper).      |
| **Media Advanced** | `analyze`               | `media-adv analyze sample_video.mp4`                                | Run the full suite of advanced media analyses: forensics, deepfake, provenance, and AI trace. |
|               | `forensics`             | `media-adv forensics sample_image.jpg`                              | Perform forensic artifact scan (ELA, PRNU, clone detection) on an image.                      |
|               | `deepfake`              | `media-adv deepfake sample_video.mp4`                               | Run heuristic-based deepfake detection (visual and audio) on a media file.                    |
|               | `provenance`            | `media-adv provenance sample_image.png`                             | Check for C2PA / content credentials in a media file.                                         |
|               | `ai-trace`              | `media-adv ai-trace sample_image.png`                               | Trace media origin to a GenAI model via metadata.                                             |
|               | `synthetic-media-audit` | `media-adv synthetic-media-audit sample_image.png`                  | Run a specialized audit to categorize and score AI-generated content.                         |
|               | `encode-covert`         | `media-adv encode-covert secret.png -m "Top Secret" -o encoded.png` | Hide a secret message in an image using LSB steganography.                                    |
|               | `decode-covert`         | `media-adv decode-covert encoded.png`                               | Extract a secret message hidden in an image using LSB steganography.                          |
| **Media forensic tools** | `exif`            | `media-tools exif /path/to/image.jpg`                                            | Extracts all metadata from a media file using ExifTool.               |
|                 | `ela`             | `media-tools ela /path/to/image.jpg /path/to/output.png --quality 90 --scale 10` | Performs Error Level Analysis (ELA) on an image.                      |
|                 | `ffmpeg-metadata` | `media-tools ffmpeg-metadata /path/to/video.mp4`                                 | Extracts video and stream metadata using FFprobe.                     |
|                 | `ffmpeg-frames`   | `media-tools ffmpeg-frames /path/to/video.mp4 /output/dir --rate 1`              | Extracts frames from a video at a specified rate (frames per second). |
|                 | `find-faces`      | `media-tools find-faces /path/to/image.jpg`                                      | Detects faces in an image and returns their locations.                |
|                 | `ssim`            | `media-tools ssim /path/to/image1.jpg /path/to/image2.jpg`                       | Calculates Structural Similarity Index (SSIM) between two images.     |
| **Playbook**  | `list`                        | `chimera auto playbook list`                                                                         | Lists all available example playbooks for workflows.                                                      |
|               | `show`                        | `chimera auto playbook show passive-asset-discovery > discovery.yaml`                                | Shows the YAML content of a specified example playbook.                                                   |
| **Voice-match** | `adversary-voice-match` | `voice-match adversary-voice-match ./samples/new_audio.wav --threshold 0.85 -o results.json` | Compares a new audio file against a library of known adversary synthetic voices using DTW. Returns similarity scores and flags matches above the threshold. |








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