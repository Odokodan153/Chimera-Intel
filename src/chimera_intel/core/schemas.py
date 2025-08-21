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
    sec_filings_analysis: Optional[SECFilingAnalysis] = None


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


class CloudOSINTResult(BaseModel):
    """The main, top-level result model for a cloud OSINT scan."""

    target_keyword: str
    found_buckets: List[S3Bucket] = []
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


# --- Third-Party Risk Management (TPRM) Models ---


class TPRMReport(BaseModel):
    """Model for an aggregated Third-Party Risk Management report."""

    target_domain: str
    ai_summary: Optional[str] = None
    vulnerability_scan_results: VulnerabilityScanResult
    breach_results: HIBPResult
    error: Optional[str] = None
