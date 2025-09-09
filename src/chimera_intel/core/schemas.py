# src/chimera_intel/core/schemas.py


from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union

# --- General Purpose Models ---


class ScoredResult(BaseModel):
    """A model for a result that has sources and a confidence score."""

    domain: Optional[str] = None
    technology: Optional[str] = None
    confidence: str
    sources: List[str]
    threat_intel: Optional["ThreatIntelResult"] = None


# --- Threat Intelligence Models ---


class PulseInfo(BaseModel):
    """Model for a single Threat Pulse from OTX."""

    name: str
    malware_families: List[str] = []
    tags: List[str] = []


class ThreatIntelResult(BaseModel):
    """Model for the threat intelligence context of an indicator."""

    indicator: str
    pulse_count: int = 0
    is_malicious: bool = False
    pulses: List[PulseInfo] = []
    error: Optional[str] = None


# --- Footprint Module Models ---


class SubdomainReport(BaseModel):
    """A model for the subdomain report, including total count and detailed results."""

    total_unique: int
    results: List[ScoredResult]


class FootprintData(BaseModel):
    """A model for the nested data within the footprint module."""

    whois_info: Dict[str, Any]
    dns_records: Dict[str, Any]
    subdomains: SubdomainReport
    ip_threat_intelligence: List[ThreatIntelResult]


class FootprintResult(BaseModel):
    """The main, top-level result model for a footprint scan."""

    domain: str
    footprint: FootprintData


# --- Web Analyzer Module Models ---


class TechStackReport(BaseModel):
    """A model for the technology stack report."""

    total_unique: int
    results: List[ScoredResult]


class WebAnalysisData(BaseModel):
    """A model for the nested data within the web analyzer module."""

    tech_stack: TechStackReport
    traffic_info: Dict[str, Any]
    screenshot_path: Optional[str] = None


class WebAnalysisResult(BaseModel):
    """The main, top-level result model for a web analysis scan."""

    domain: str
    web_analysis: WebAnalysisData


# --- Business Intelligence Models ---


class Financials(BaseModel):
    """Model for key financial metrics from Yahoo Finance."""

    companyName: Optional[str] = None
    sector: Optional[str] = None
    marketCap: Optional[int] = None
    trailingPE: Optional[float] = None
    forwardPE: Optional[float] = None
    dividendYield: Optional[float] = None
    error: Optional[str] = None


class NewsArticle(BaseModel):
    """Model for a single news article from GNews."""

    title: str
    description: str
    url: str
    source: Dict[str, Any]


class GNewsResult(BaseModel):
    """Model for the entire response from GNews API."""

    totalArticles: Optional[int] = None
    articles: Optional[List[NewsArticle]] = None
    error: Optional[str] = None


class Patent(BaseModel):
    """Model for a single patent scraped from Google Patents."""

    title: str
    link: str


class PatentResult(BaseModel):
    """Model for the list of scraped patents."""

    patents: Optional[List[Patent]] = None
    error: Optional[str] = None


class SECFilingAnalysis(BaseModel):
    """Model for the analysis of a specific SEC filing."""

    filing_url: str
    filing_type: str = "10-K"
    risk_factors_summary: Optional[str] = None
    error: Optional[str] = None


class BusinessIntelData(BaseModel):
    """The nested object containing all business intelligence data."""

    # The 'financials' field can be either a structured object or a simple string

    financials: Union[Financials, str]
    news: GNewsResult
    patents: PatentResult


class BusinessIntelResult(BaseModel):
    """The final, top-level model for a business intelligence scan."""

    company: str
    business_intel: BusinessIntelData


# --- Defensive Module Models ---


class HIBPBreach(BaseModel):
    """Model for a single data breach entry from Have I Been Pwned."""

    Name: str
    Title: str
    Domain: str
    BreachDate: str
    PwnCount: int
    Description: str
    DataClasses: List[str]
    IsVerified: bool


class HIBPResult(BaseModel):
    """Model for the result of a HIBP domain breach check."""

    breaches: Optional[List[HIBPBreach]] = None
    message: Optional[str] = None
    error: Optional[str] = None


class GitHubLeakItem(BaseModel):
    """Model for a single code leak item found on GitHub."""

    url: str
    repository: str


class GitHubLeaksResult(BaseModel):
    """Model for the result of a GitHub code leak search."""

    total_count: Optional[int] = None
    items: Optional[List[GitHubLeakItem]] = None
    error: Optional[str] = None


class TyposquatFuzzer(BaseModel):
    """Model for a single typosquatting variation from dnstwist."""

    fuzzer: str
    domain_name: str = Field(..., alias="domain-name")
    dns_a: Optional[List[str]] = Field(None, alias="dns-a")
    dns_aaaa: Optional[List[str]] = Field(None, alias="dns-aaaa")
    dns_mx: Optional[List[str]] = Field(None, alias="dns-mx")
    dns_ns: Optional[List[str]] = Field(None, alias="dns-ns")


class TyposquatResult(BaseModel):
    """Model for the result of a dnstwist typosquatting scan."""

    results: Optional[List[TyposquatFuzzer]] = None
    error: Optional[str] = None


class ShodanHost(BaseModel):
    """Model for a single host found by Shodan."""

    ip: Optional[str] = None
    port: Optional[int] = None
    org: Optional[str] = None
    hostnames: Optional[List[str]] = None
    data: Optional[str] = None


class ShodanResult(BaseModel):
    """Model for the result of a Shodan scan."""

    total_results: int = 0
    hosts: List[ShodanHost] = []
    error: Optional[str] = None


class Paste(BaseModel):
    """Model for a single paste from paste.ee."""

    id: str
    link: str
    description: Optional[str] = None


class PasteResult(BaseModel):
    """Model for the result of a paste search."""

    pastes: List[Paste] = []
    count: int = 0
    error: Optional[str] = None


class SSLLabsResult(BaseModel):
    """A flexible model to hold the entire JSON response from SSL Labs."""

    # We use Dict[str, Any] because the report is very complex and variable

    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class MobSFResult(BaseModel):
    """A flexible model to hold the entire JSON response from MobSF."""

    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# --- Social Analyzer Models ---


class AnalyzedPost(BaseModel):
    """Model for a single, AI-analyzed blog post from an RSS feed."""

    title: str
    link: str
    top_category: str
    confidence: str


class SocialContentAnalysis(BaseModel):
    """Model for the analysis results of an entire RSS feed."""

    feed_title: str
    posts: List[AnalyzedPost]
    error: Optional[str] = None


class SocialAnalysisResult(BaseModel):
    """The main, top-level result model for a social content analysis scan."""

    domain: str
    social_content_analysis: SocialContentAnalysis


# --- Main Application Configuration Models (from config.yaml) ---


class ConfigFootprint(BaseModel):
    """Configuration for the footprint module from config.yaml."""

    dns_records_to_query: List[str] = ["A", "MX"]


class ConfigDarkWeb(BaseModel):
    """Configuration for the dark web module from config.yaml."""

    tor_proxy_url: str = "socks5://127.0.0.1:9150"


# --- AI Core Models ---


class SentimentAnalysisResult(BaseModel):
    """Model for the result of a sentiment analysis."""

    label: str
    score: float
    error: Optional[str] = None


class SWOTAnalysisResult(BaseModel):
    """Model for the result of a SWOT analysis from the AI model."""

    analysis_text: str
    error: Optional[str] = None


class AnomalyDetectionResult(BaseModel):
    """Model for the result of a traffic anomaly detection."""

    data_points: List[Any]
    detected_anomalies: List[float]
    error: Optional[str] = None


# --- Signal Analyzer Models ---


class JobPostingsResult(BaseModel):
    """Model for the result of a job postings scrape."""

    job_postings: List[str]
    error: Optional[str] = None


class StrategicSignal(BaseModel):
    """Model for a single detected strategic signal."""

    category: str
    signal: str
    source: str


# --- Strategist Models ---


class StrategicProfileResult(BaseModel):
    """Model for the result of an AI-generated strategic profile."""

    profile_text: Optional[str] = None
    error: Optional[str] = None


# --- Differ Models ---


class FormattedDiff(BaseModel):
    """A simplified, human-readable format for scan differences."""

    added: List[str] = Field(default_factory=list)
    removed: List[str] = Field(default_factory=list)
    changed: List[str] = Field(default_factory=list)


class DiffResult(BaseModel):
    """Model for the result of a full scan comparison."""

    comparison_summary: FormattedDiff
    raw_diff: Dict[str, Any]
    error: Optional[str] = None


# --- Forecaster Models ---


class Prediction(BaseModel):
    """Model for a single predictive insight or forecast."""

    signal: str
    details: str


class ForecastResult(BaseModel):
    """Model for the list of all forecasts for a target."""

    predictions: List[Prediction]
    notes: Optional[str] = None  # For messages like "Not enough data"


# --- Vulnerability Scanner Models ---


class CVE(BaseModel):
    """Model for a single CVE entry from Vulners."""

    id: str
    cvss_score: float = Field(..., alias="cvss")
    title: str


class PortDetail(BaseModel):
    """Model for details about a single open port."""

    port: int
    state: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: List[CVE] = []


class HostScanResult(BaseModel):
    """Model for the full Nmap scan results for a single host."""

    host: str
    state: str
    open_ports: List[PortDetail]
    error: Optional[str] = None


class VulnerabilityScanResult(BaseModel):
    """The main, top-level result model for a vulnerability scan."""

    target_domain: str
    scanned_hosts: List[HostScanResult]
    error: Optional[str] = None


# --- Social Media OSINT Models ---


class SocialProfile(BaseModel):
    """Model for a single social media profile found."""

    name: str
    url: str


class SocialOSINTResult(BaseModel):
    """The main, top-level result model for a social media OSINT scan."""

    username: str
    found_profiles: List[SocialProfile]
    error: Optional[str] = None


# --- Dark Web OSINT Models ---


class DarkWebResult(BaseModel):
    """Model for a single search result from a dark web search engine."""

    title: str
    url: str
    description: Optional[str] = None


class DarkWebScanResult(BaseModel):
    """The main, top-level result model for a dark web scan."""

    query: str
    found_results: List[DarkWebResult]
    error: Optional[str] = None


# --- Cloud OSINT Models ---


class S3Bucket(BaseModel):
    """Model for a single discovered S3 bucket."""

    name: str
    url: str
    is_public: bool


class AzureBlobContainer(BaseModel):
    """Model for a single discovered Azure Blob container."""

    name: str
    url: str
    is_public: bool


class GCSBucket(BaseModel):
    """Model for a single discovered Google Cloud Storage bucket."""

    name: str
    url: str
    is_public: bool


class CloudOSINTResult(BaseModel):
    """The main, top-level result model for a cloud OSINT scan."""

    target_keyword: str
    found_s3_buckets: List[S3Bucket] = []
    found_azure_containers: List[AzureBlobContainer] = []
    found_gcs_buckets: List[GCSBucket] = []
    error: Optional[str] = None


# --- Personnel OSINT Models ---


class EmployeeProfile(BaseModel):
    """Model for a single employee profile found by Hunter.io."""

    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: str
    position: Optional[str] = None
    phone_number: Optional[str] = None


class PersonnelOSINTResult(BaseModel):
    """The main, top-level result model for a personnel OSINT scan."""

    domain: str
    organization_name: Optional[str] = None
    total_emails_found: int = 0
    employee_profiles: List[EmployeeProfile] = []
    error: Optional[str] = None


# --- Corporate Records Models ---


class Officer(BaseModel):
    """Model for a single company officer or director."""

    name: str
    position: str


class CompanyRecord(BaseModel):
    """Model for a single official company record from OpenCorporates."""

    name: str
    company_number: str
    jurisdiction: str
    registered_address: Optional[str] = None
    is_inactive: bool
    officers: List[Officer] = []


class CorporateRegistryResult(BaseModel):
    """The main, top-level result model for a corporate registry search."""

    query: str
    total_found: int = 0
    records: List[CompanyRecord] = []
    error: Optional[str] = None


class SanctionedEntity(BaseModel):
    """Model for a single entity found on the OFAC sanctions list."""

    name: str
    address: Optional[str] = None
    type: str
    programs: List[str] = []
    score: int


class SanctionsScreeningResult(BaseModel):
    """The main, top-level result model for a sanctions list screening."""

    query: str
    hits_found: int = 0
    entities: List[SanctionedEntity] = []
    error: Optional[str] = None


class PEPScreeningResult(BaseModel):
    """Model for the result of a PEP screening."""

    query: str
    is_pep: bool


# --- Third-Party Risk Management (TPRM) Models ---


class TPRMReport(BaseModel):
    """Model for an aggregated Third-Party Risk Management report."""

    target_domain: str
    ai_summary: Optional[str] = None
    vulnerability_scan_results: VulnerabilityScanResult
    breach_results: HIBPResult
    error: Optional[str] = None


# --- Geo OSINT Models ---


class GeoIntelData(BaseModel):
    """Model for geolocation data for a single IP address from IP-API.com."""

    query: str
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None


class GeoIntelResult(BaseModel):
    """The main, top-level result model for a geolocation OSINT scan."""

    locations: List[GeoIntelData] = []
    error: Optional[str] = None


# HR Intelligence


class JobPosting(BaseModel):
    """Model for a single job posting."""

    title: str
    location: Optional[str] = None
    department: Optional[str] = None


class HiringTrendsResult(BaseModel):
    """Model for the result of a hiring trend analysis."""

    total_postings: int
    trends_by_department: Dict[str, int] = {}
    job_postings: List[JobPosting] = []
    error: Optional[str] = None


class EmployeeSentimentResult(BaseModel):
    """Model for the result of an employee sentiment analysis."""

    overall_rating: Optional[float] = None
    ceo_approval: Optional[str] = None
    sentiment_summary: Dict[str, float] = {}
    error: Optional[str] = None


# Supply Chain Intelligence


class Shipment(BaseModel):
    """Model for a single import/export shipment."""

    date: str
    shipper: str
    consignee: str
    product_description: str
    quantity: Optional[str] = None
    weight_kg: Optional[float] = None


class TradeDataResult(BaseModel):
    """Model for the result of a trade data search."""

    total_shipments: int
    shipments: List[Shipment] = []
    error: Optional[str] = None


# Deeper IP Intelligence


class Trademark(BaseModel):
    """Model for a single trademark registration."""

    serial_number: str
    status: str
    description: str
    owner: str


class TrademarkResult(BaseModel):
    """Model for the result of a trademark search."""

    total_found: int
    trademarks: List[Trademark] = []
    error: Optional[str] = None


# Regulatory Intelligence


class LobbyingRecord(BaseModel):
    """Model for a single lobbying disclosure."""

    issue: str
    amount: int
    year: int


class LobbyingResult(BaseModel):
    """Model for the result of a lobbying activity search."""

    total_spent: int
    records: List[LobbyingRecord] = []
    error: Optional[str] = None


# --- Offensive & Reconnaissance Models ---

# API Discovery


class DiscoveredAPI(BaseModel):
    """Model for a single discovered API endpoint or specification."""

    url: str
    api_type: str  # e.g., "REST", "GraphQL", "Swagger/OpenAPI"
    status_code: int


class APIDiscoveryResult(BaseModel):
    """Model for the result of an API discovery scan."""

    target_domain: str
    discovered_apis: List[DiscoveredAPI] = []
    error: Optional[str] = None


# Content Enumeration


class DiscoveredContent(BaseModel):
    """Model for a single discovered directory or file."""

    url: str
    status_code: int
    content_length: int


class ContentEnumerationResult(BaseModel):
    """Model for the result of a content enumeration scan."""

    target_url: str
    found_content: List[DiscoveredContent] = []
    error: Optional[str] = None


# Advanced Cloud Recon


class SubdomainTakeoverResult(BaseModel):
    """Model for a potential subdomain takeover."""

    subdomain: str
    vulnerable_service: str
    details: str


class AdvancedCloudResult(BaseModel):
    """Model for the result of an advanced cloud recon scan."""

    target_domain: str
    potential_takeovers: List[SubdomainTakeoverResult] = []
    error: Optional[str] = None

    # --- Internal & Post-Breach Models ---


# Incident Response


class LogAnalysisResult(BaseModel):
    """Model for the result of a log file analysis."""

    total_lines_parsed: int
    suspicious_events: Dict[str, int] = {}
    error: Optional[str] = None


class IncidentTimelineEvent(BaseModel):
    """Model for a single event in an incident timeline."""

    timestamp: str
    source: str
    event_description: str


class IncidentTimelineResult(BaseModel):
    """Model for a generated incident timeline."""

    total_events: int
    timeline: List[IncidentTimelineEvent] = []
    error: Optional[str] = None


# Malware Analysis


class StaticAnalysisResult(BaseModel):
    """Model for the static analysis of a file."""

    filename: str
    file_size: int
    hashes: Dict[str, str] = {}  # e.g., {"md5": "...", "sha256": "..."}
    embedded_strings: List[str] = []
    error: Optional[str] = None


# Forensic Artifact Analysis


class MFTEntry(BaseModel):
    """Model for a single entry from a parsed MFT."""

    record_number: int
    filename: str
    creation_time: str
    modification_time: str
    is_directory: bool


class MFTAnalysisResult(BaseModel):
    """Model for the result of a Master File Table analysis."""

    total_records: int
    entries: List[MFTEntry] = []
    error: Optional[str] = None


# --- Proactive & Defensive Models ---

# Certificate Transparency


class Certificate(BaseModel):
    """Model for a single certificate found in CT logs."""

    issuer_name: str
    not_before: str
    not_after: str
    subject_name: str


class CTMentorResult(BaseModel):
    """Model for the result of a Certificate Transparency log search."""

    domain: str
    total_found: int
    certificates: List[Certificate] = []
    error: Optional[str] = None


# IaC Scanning


class IaCSecurityIssue(BaseModel):
    """Model for a single security issue found in an IaC file."""

    file_path: str
    line_number: int
    issue_id: str
    description: str
    severity: str  # e.g., "High", "Medium", "Low"


class IaCScanResult(BaseModel):
    """Model for the result of an Infrastructure as Code scan."""

    target_path: str
    total_issues: int
    issues: List[IaCSecurityIssue] = []
    error: Optional[str] = None


# Secrets Scanning


class FoundSecret(BaseModel):
    """Model for a single hardcoded secret found in a file."""

    file_path: str
    line_number: int
    rule_id: str
    secret_type: str  # e.g., "AWS Access Key", "Generic API Key"


class SecretsScanResult(BaseModel):
    """Model for the result of a secrets scan."""

    target_path: str
    total_found: int
    secrets: List[FoundSecret] = []
    error: Optional[str] = None


# --- Analysis & Automation Models ---

# Data Enrichment


class EnrichedIOC(BaseModel):
    """Model for a single, enriched Indicator of Compromise."""

    indicator: str
    is_malicious: bool
    source: str  # e.g., "OTX", "Local DB"
    details: Optional[str] = None


class EnrichmentResult(BaseModel):
    """Model for the result of an IOC enrichment task."""

    total_enriched: int
    enriched_iocs: List[EnrichedIOC] = []
    error: Optional[str] = None


# Threat Modeling


class AttackPath(BaseModel):
    """Model for a single potential attack path."""

    entry_point: str
    path: List[str]
    target: str
    confidence: str  # e.g., "High", "Medium"


class ThreatModelResult(BaseModel):
    """Model for a generated threat model."""

    target_domain: str
    potential_paths: List[AttackPath] = []
    error: Optional[str] = None


# UEBA


class BehavioralBaseline(BaseModel):
    """Model for a user's normal behavioral baseline."""

    user: str
    typical_login_hours: List[int]
    common_source_ips: List[str]


class BehavioralAnomaly(BaseModel):
    """Model for a single detected behavioral anomaly."""

    timestamp: str
    user: str
    anomaly_description: str
    severity: str


class UEBAResult(BaseModel):
    """Model for the result of a UEBA log analysis."""

    total_anomalies_found: int
    anomalies: List[BehavioralAnomaly] = []
    error: Optional[str] = None


# CVE Enrichment


class EnrichedCVE(BaseModel):
    """Model for a single, enriched CVE."""

    cve_id: str
    cvss_score: float
    summary: str
    references: List[str] = []


class CVEEnrichmentResult(BaseModel):
    """Model for the result of a CVE enrichment task."""

    total_enriched: int
    enriched_cves: List[EnrichedCVE] = []
    error: Optional[str] = None


# Integration Results


class VTSubmissionResult(BaseModel):
    """Model for a VirusTotal file/URL submission result."""

    resource_id: str
    permalink: str
    response_code: int
    verbose_msg: str
    error: Optional[str] = None


# Credential Reconnaissance


class CompromisedCredential(BaseModel):
    """Model for a single compromised credential found in a leak."""

    email: str
    source_breach: str
    password_hash: Optional[str] = None
    is_plaintext: bool = False


class CredentialExposureResult(BaseModel):
    """Model for the result of a credential leak search."""

    target_domain: str
    total_found: int
    compromised_credentials: List[CompromisedCredential] = []
    error: Optional[str] = None


# Digital Asset Intelligence


class MobileApp(BaseModel):
    """Model for an analyzed mobile application."""

    app_name: str
    app_id: str
    store: str  # "Google Play" or "Apple App Store"
    developer: str
    permissions: List[str] = []
    embedded_endpoints: List[str] = []


class AssetIntelResult(BaseModel):
    """Model for the result of a digital asset intelligence scan."""

    target_company: str
    mobile_apps: List[MobileApp] = []
    public_datasets: List[str] = []
    error: Optional[str] = None


# Threat Infrastructure Reconnaissance


class RelatedIndicator(BaseModel):
    """Model for an indicator related to a malicious asset."""

    indicator_type: str  # e.g., "IP Address", "Domain"
    value: str
    relation: str  # e.g., "Hosted on", "Communicated with"


class ThreatInfraResult(BaseModel):
    """Model for the result of a threat infrastructure analysis."""

    initial_indicator: str
    related_indicators: List[RelatedIndicator] = []
    error: Optional[str] = None


# --- NEW: Add models for PDF reporting configuration ---


class ConfigPDF(BaseModel):
    """Configuration for PDF report generation."""

    logo_path: Optional[str] = None
    title_text: str = "Chimera Intel - Intelligence Report"
    footer_text: str = "Confidential | Prepared by Chimera Intel"


class ConfigReporting(BaseModel):
    """Configuration for all reporting."""

    graph: Dict[str, Any] = {}
    pdf: ConfigPDF = ConfigPDF()


class ConfigModules(BaseModel):
    """Configuration for all modules from config.yaml."""

    footprint: ConfigFootprint
    dark_web: ConfigDarkWeb


class ConfigNetwork(BaseModel):
    """General network settings from config.yaml."""

    timeout: float = 20.0


class AppConfig(BaseModel):
    """The main model for validating the entire config.yaml file."""

    network: ConfigNetwork
    modules: ConfigModules
    reporting: ConfigReporting = ConfigReporting()


# --- Blockchain & Cryptocurrency OSINT Models ---


class WalletTransaction(BaseModel):
    """Model for a single blockchain transaction."""

    hash: str
    from_address: str = Field(..., alias="from")
    to_address: str = Field(..., alias="to")
    value_eth: str
    timestamp: str


class WalletAnalysisResult(BaseModel):
    """Model for the analysis of a single cryptocurrency wallet."""

    address: str
    balance_eth: str
    total_transactions: int
    recent_transactions: List[WalletTransaction] = []
    error: Optional[str] = None

    # --- Code & Repository Intelligence Models ---


class CommitterInfo(BaseModel):
    """Model for information about a single code committer."""

    name: str
    email: str
    commit_count: int


class RepoAnalysisResult(BaseModel):
    """Model for the result of a full repository analysis."""

    repository_url: str
    total_commits: int
    total_committers: int
    top_committers: List[CommitterInfo] = []
    commit_keywords: Dict[str, int] = {}
    error: Optional[str] = None
    # --- Adversary Emulation & TTP Mapping Models ---


class MappedTechnique(BaseModel):
    """Model for a single MITRE ATT&CK technique mapped to a CVE."""

    cve_id: str
    technique_id: str
    technique_name: str
    tactic: str


class TTPMappingResult(BaseModel):
    """Model for the result of a CVE to TTP mapping analysis."""

    total_cves_analyzed: int
    mapped_techniques: List[MappedTechnique] = []
    error: Optional[str] = None


# --- Physical Security OSINT Models ---


class PhysicalLocation(BaseModel):
    """Model for a single discovered physical location."""

    name: str
    address: str
    latitude: float
    longitude: float
    rating: Optional[float] = None


class PhysicalSecurityResult(BaseModel):
    """Model for the result of a physical security OSINT scan."""

    query: str
    locations_found: List[PhysicalLocation] = []
    error: Optional[str] = None
