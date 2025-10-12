from typing import Any, Dict, List, Optional, Union
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Boolean,
    LargeBinary,
    Enum as SQLAlchemyEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime 
from pydantic import BaseModel, Field, validator, EmailStr
import uuid
from enum import Enum

# --- General Purpose Models ---

Base = declarative_base()

class ScoredResult(BaseModel):
    """A model for a result that has sources and a confidence score."""

    domain: Optional[str] = None
    technology: Optional[str] = None
    confidence: str
    sources: List[str]
    threat_intel: Optional["ThreatIntelResult"] = None

class ScanData(BaseModel):
    """A model for a single scan result."""

    id: int
    module: str
    data: Dict[str, Any]


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


class TechStackRisk(BaseModel):
    """Model for the risk assessment of a technology stack."""

    risk_score: int
    risk_level: str  # e.g., "Low", "Medium", "High", "Critical"
    summary: str
    details: List[str] = []


class WebAnalysisData(BaseModel):
    """A model for the nested data within the web analyzer module."""

    tech_stack: TechStackReport
    traffic_info: Dict[str, Any]
    screenshot_path: Optional[str] = None
    tech_risk_assessment: Optional[TechStackRisk] = None


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


# --- Forecaster Models ---


class Prediction(BaseModel):
    """Model for a single predictive insight or forecast."""

    signal: str
    details: str


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

    project_report_scans: List[str] = Field(
        default_factory=lambda: ["footprint", "web_analyzer", "defensive_breaches"]
    )
    graph: Dict[str, Any] = {}
    pdf: ConfigPDF = ConfigPDF()


class ConfigModules(BaseModel):
    """Configuration for all modules from config.yaml."""

    footprint: ConfigFootprint
    dark_web: ConfigDarkWeb


class ConfigNetwork(BaseModel):
    """General network settings from config.yaml."""

    timeout: float = 20.0


class ConfigNotifications(BaseModel):
    """Configuration for notifications from config.yaml."""
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None


class ConfigGraphDB(BaseModel):
    """Configuration for the graph database from config.yaml."""
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"

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


# --- Ecosystem Intelligence Models ---


class DiscoveredPartner(BaseModel):
    """Model for a single discovered business partner."""

    partner_name: str
    source: str  # e.g., "Press Release", "Partner Page", "Tech Stack"
    details: str
    confidence: str  # "High", "Medium", "Low"


class DiscoveredCompetitor(BaseModel):
    """Model for a single discovered competitor."""

    competitor_name: str
    source: str  # e.g., "SimilarWeb API", "Market Sector Analysis"
    details: Optional[str] = None
    confidence: str  # "High", "Medium", "Low"


class DiscoveredDistributor(BaseModel):
    """Model for a single discovered distributor, retailer, or supply chain partner."""

    distributor_name: str
    location: Optional[str] = None  # e.g., "Germany", "New York, USA"
    source: str  # e.g., "Trade Data", "Website Scrape"
    details: Optional[str] = None  # e.g., "Consignee in 15 shipments"
    confidence: str  # "High", "Medium", "Low"


class EcosystemData(BaseModel):
    """Model for all discovered ecosystem relationships."""

    partners: List[DiscoveredPartner] = []
    competitors: List[DiscoveredCompetitor] = []
    distributors: List[DiscoveredDistributor] = []


class EcosystemResult(BaseModel):
    """The main, top-level result model for an ecosystem intelligence scan."""

    target_company: str
    ecosystem_data: EcosystemData
    error: Optional[str] = None


class MozillaObservatoryResult(BaseModel):
    """
    A model to hold the summary of a Mozilla Observatory scan.
    The full report can be very large, so we capture the key metrics.
    """

    scan_id: int
    score: int
    grade: str
    state: str
    tests_passed: int
    tests_failed: int
    report_url: str
    error: Optional[str] = None


# --- Cyber Intelligence (CYBINT) Models ---


class AttackSurfaceReport(BaseModel):
    """Model for a comprehensive, AI-analyzed attack surface report."""

    target_domain: str
    ai_risk_assessment: str
    full_footprint_data: FootprintResult
    vulnerability_scan_results: VulnerabilityScanResult
    web_security_posture: Optional[MozillaObservatoryResult] = None
    api_discovery_results: APIDiscoveryResult
    error: Optional[str] = None


class TTP(BaseModel):
    """Model for a single Tactic, Technique, or Procedure used by an adversary."""

    technique_id: str  # e.g., T1566.001
    tactic: str  # e.g., Initial Access
    description: str


class ThreatActor(BaseModel):
    """Model for a single threat actor profile."""

    name: str  # e.g., "APT28", "FIN7"
    aliases: List[str] = []
    targeted_industries: List[str] = []
    known_ttps: List[TTP] = []
    known_indicators: List[str] = []  # Malicious IPs, domains, hashes


class ThreatActorIntelResult(BaseModel):
    """The result of a threat actor intelligence gathering operation."""

    actor: Optional[ThreatActor] = None
    error: Optional[str] = None


# --- Legal Intelligence (LEGINT) Models ---


class CourtRecord(BaseModel):
    """Model for a single court docket record from CourtListener."""

    case_name: str = Field(..., alias="caseName")
    date_filed: str = Field(..., alias="dateFiled")
    court: str
    docket_url: str = Field(..., alias="absolute_url")
    docket_number: str = Field(..., alias="docketNumber")


class DocketSearchResult(BaseModel):
    """The main, top-level result model for a court docket search."""

    query: str
    total_found: int = 0
    records: List[CourtRecord] = []
    error: Optional[str] = None


# --- Geo-Strategic Intelligence Models ---


class OperationalCenter(BaseModel):
    """Model for a single identified center of operations."""

    location_name: Optional[str] = None
    address: Optional[str] = None
    location_type: str  # e.g., "Corporate Office", "Hiring Area", "Distribution Hub"
    source_modules: List[str]
    details: str


class GeoStrategicReport(BaseModel):
    """The main, top-level result model for a geo-strategic analysis."""

    target: str
    operational_centers: List[OperationalCenter] = []
    error: Optional[str] = None


# --- Financial Intelligence (FININT) Models ---


class InsiderTransaction(BaseModel):
    """Model for a single insider trading transaction."""

    companyName: str
    insiderName: str
    transactionType: str
    transactionDate: str
    shares: int
    value: Optional[int] = None


class InsiderTradingResult(BaseModel):
    """The main, top-level result model for an insider trading scan."""

    ticker: str
    total_transactions: int = 0
    transactions: List[InsiderTransaction] = []
    error: Optional[str] = None


# --- PESTEL Analysis Models ---


class PESTELAnalysisResult(BaseModel):
    """Model for the result of a PESTEL analysis from the AI model."""

    analysis_text: str
    error: Optional[str] = None


# --- Competitive Analysis Models ---


class CompetitiveAnalysisResult(BaseModel):
    """Model for the result of a competitive analysis from the AI model."""

    analysis_text: str
    error: Optional[str] = None


# --- Project Management & Daemon Models ---


class ScheduledWorkflow(BaseModel):
    """A single, named workflow with a cron schedule."""

    name: str
    schedule: str  # e.g., "0 * * * *" for hourly
    steps: List[str]


class DaemonConfig(BaseModel):
    """Configuration for the autonomous monitoring daemon."""

    enabled: bool = False
    # Replaces monitoring_interval_hours and workflow
    workflows: List[ScheduledWorkflow] = [
        ScheduledWorkflow(
            name="daily_footprint_diff",
            schedule="0 8 * * *",  # Default: 8 AM every day
            steps=[
                "scan footprint {target}",
                "analysis diff run footprint {target}",
            ],
        )
    ]


class ProjectConfig(BaseModel):
    """Model for validating a project's configuration file (project.yaml)."""

    project_name: str
    created_at: str

    # Core Assets
    domain: Optional[str] = None
    company_name: Optional[str] = None
    ticker: Optional[str] = None
    key_personnel: List[str] = []
    known_ips: List[str] = []

    # Daemon Configuration
    daemon_config: DaemonConfig = DaemonConfig()


# --- Lead Suggestion Models ---


class LeadSuggestionResult(BaseModel):
    """Model for the result of an AI-powered lead suggestion task."""

    suggestions_text: str
    error: Optional[str] = None


# --- Briefing Generator Models ---


class BriefingResult(BaseModel):
    """Model for a full, AI-generated intelligence briefing."""

    title: Optional[str] = None
    briefing_text: str
    error: Optional[str] = None


# --- Real-Time Social Media Monitoring Models ---


class Tweet(BaseModel):
    """Model for a single tweet from the Twitter/X API."""

    id: str
    text: str
    author_id: str
    created_at: str


class TwitterMonitoringResult(BaseModel):
    """The main, top-level result model for a real-time social media monitoring session."""

    query: str
    total_tweets_found: int = 0
    tweets: List[Tweet] = []
    error: Optional[str] = None


class YouTubeVideo(BaseModel):
    """Model for a single YouTube video."""

    id: str
    title: str
    channel_id: str
    channel_title: str
    published_at: str


class YouTubeMonitoringResult(BaseModel):
    """The main, top-level result model for a real-time YouTube monitoring session."""

    query: str
    total_videos_found: int = 0
    videos: List[YouTubeVideo] = []
    error: Optional[str] = None


# --- Mobile Application Intelligence (APPINT) Models ---


class StaticAppAnalysisResult(BaseModel):
    """Model for the static analysis of a mobile application file."""

    file_path: str
    secrets_found: List[FoundSecret] = []
    error: Optional[str] = None


# --- Image & Video Intelligence (IMINT/VIDINT) Models ---


class ExifData(BaseModel):
    """Model for extracted EXIF metadata from an image."""

    Make: Optional[str] = None
    Model: Optional[str] = None
    DateTime: Optional[str] = None
    GPSInfo: Optional[Dict[str, Any]] = None


class ImageAnalysisResult(BaseModel):
    """The main, top-level result model for an image analysis."""

    file_path: str
    exif_data: Optional[ExifData] = None
    message: Optional[str] = None
    error: Optional[str] = None


# --- Geopolitical Intelligence (GEOINT) Models ---


class CountryRiskProfile(BaseModel):
    """Model for a country's geopolitical and economic risk profile."""

    country_name: str
    region: Optional[str] = None
    subregion: Optional[str] = None
    population: Optional[int] = None
    political_stability_index: Optional[float] = None
    economic_freedom_index: Optional[float] = None


class GeointReport(BaseModel):
    """The main, top-level result model for a GEOINT analysis."""

    target: str
    country_risk_profiles: List[CountryRiskProfile] = []
    error: Optional[str] = None


# --- Operational Security (OPSEC) Models ---


class CompromisedCommitter(BaseModel):
    """Model for a code committer whose credentials may be compromised."""

    email: str
    source_repository: Optional[str] = None
    related_breaches: List[str] = []


class OpsecReport(BaseModel):
    """The main, top-level result model for an OPSEC analysis."""

    target: str
    compromised_committers: List[CompromisedCommitter] = []
    error: Optional[str] = None


# --- Temporal Analysis Models ---


class TemporalSnapshot(BaseModel):
    """Model for a single historical snapshot of a website from the Wayback Machine."""

    url: str
    timestamp: str
    status_code: int


class ShiftingIdentityResult(BaseModel):
    """The main, top-level result model for a shifting identity analysis."""

    domain: str
    total_snapshots_found: int
    snapshots: List[TemporalSnapshot] = []
    error: Optional[str] = None


# --- Micro-OSINT & Anomaly Models ---


class MicroSignal(BaseModel):
    """Model for a single, interpreted micro-signal detected from a scan diff."""

    signal_type: str  # e.g., "Infrastructure Change", "Security Posture Degradation"
    description: str
    confidence: str  # e.g., "High", "Medium", "Low"
    source_field: str  # The specific field in the data where the change was detected


class DiffResult(BaseModel):
    """Model for the result of a full scan comparison."""

    comparison_summary: FormattedDiff
    detected_signals: List[MicroSignal] = []
    raw_diff: Dict[str, Any]
    error: Optional[str] = None


# --- Weak Signal Amplification Models ---


class WeakSignal(BaseModel):
    """Model for a single weak signal or piece of evidence."""

    source_module: str
    signal_type: str  # A label for the type of event this signal might indicate
    description: str
    belief: float  # The degree of belief in this signal (e.g., 0.3 for 30%)


class AmplifiedEventResult(BaseModel):
    """Model for the result of a Weak Signal Amplification analysis."""

    event_hypothesis: str
    combined_belief: float
    contributing_signals: List[WeakSignal]
    summary: str
    error: Optional[str] = None


# --- Corporate Network & Deception Models ---


class CorporateNetworkLink(BaseModel):
    """Model for a single detected link between two corporate entities."""

    entity_a: str
    entity_b: str
    link_type: str  # e.g., "Shared IP Address", "Shared SSL Certificate", "Shared Whois Contact"
    confidence: str  # "High", "Medium", "Low"
    details: str


class DeceptionAnalysisResult(BaseModel):
    """The main, top-level result model for a corporate deception analysis."""

    target: str
    detected_links: List[CorporateNetworkLink] = []
    summary: str
    error: Optional[str] = None


# --- Image & Video Intelligence (IMINT/VIDINT) Models ---


class ReverseImageMatch(BaseModel):
    """Model for a single match from a reverse image search."""

    page_url: str
    page_title: str
    image_url: str
    source_engine: str  # e.g., "Google Images", "TinEye"


class ReverseImageSearchResult(BaseModel):
    """The main result model for a reverse image search operation."""

    source_image_path: str
    matches_found: int = 0
    matches: List[ReverseImageMatch] = []
    error: Optional[str] = None


class MediaTranscript(BaseModel):
    """Model for a transcript generated from an audio or video file."""

    language: str
    text: str
    confidence: float


class MediaAnalysisResult(BaseModel):
    """The main result model for analyzing an audio or video file."""

    file_path: str
    media_type: str  # "Audio" or "Video"
    transcript: Optional[MediaTranscript] = None
    error: Optional[str] = None


# --- Behavioral Intelligence Models ---


class NarrativeEntropy(BaseModel):
    """Model for the narrative entropy analysis of a target."""

    entropy_score: float
    assessment: str  # e.g., "Highly Focused Narrative", "Diverse Narrative"
    top_keywords: List[str] = []


class BehavioralSignal(BaseModel):
    """Model for a single behavioral or cultural indicator."""

    source_type: str  # e.g., "Job Posting", "Press Release"
    signal_type: str  # e.g., "Risk Tolerance", "Innovation Focus"
    content: str
    justification: str


class PsychographicProfileResult(BaseModel):
    """Model for the result of a full psychographic and behavioral analysis."""

    target: str
    profile_summary: Dict[str, Any] = {}
    behavioral_signals: List[BehavioralSignal] = []
    narrative_entropy: Optional[NarrativeEntropy] = None
    error: Optional[str] = None


# --- Forecaster & Anomaly Models ---


class ExpectedEvent(BaseModel):
    """Defines a pattern for an expected, recurring event."""

    event_type: str  # e.g., "Quarterly Report", "Security Bulletin"
    module: str
    field_to_check: str  # e.g., "news.articles"
    expected_frequency_days: int


class ForecastResult(BaseModel):
    """Model for the list of all forecasts for a target."""

    predictions: List[Prediction]
    missed_events: List[str] = []  # For OSINT via Negative Space
    notes: Optional[str] = None


# --- Podcast Intelligence Models ---


class PodcastEpisode(BaseModel):
    """Model for a single podcast episode from an RSS feed."""

    title: str
    published_date: str = Field(..., alias="published")
    summary: Optional[str] = None
    audio_url: Optional[str] = None


class PodcastInfoResult(BaseModel):
    """Model for the result of a podcast RSS feed analysis."""

    feed_url: str
    title: Optional[str] = None
    author: Optional[str] = None
    episodes: List[PodcastEpisode] = []
    error: Optional[str] = None


class PodcastSearchResult(BaseModel):
    """Model for the result of searching within a podcast episode."""

    episode_audio_url: str
    keyword: str
    is_found: bool
    transcript_snippet: Optional[str] = None
    error: Optional[str] = None


class PodcastAnalysisResult(BaseModel):
    """Model for the result of an AI-powered analysis of a podcast episode."""

    episode_audio_url: str
    analysis_text: str
    error: Optional[str] = None



# ---: User Management Models ---
class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    owner_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


# --- Threat Hunter Models ---
class DetectedIOC(BaseModel):
    """Model for a single IOC detected in a log file."""

    ioc: str
    line_number: int
    log_line: str


class ThreatHuntResult(BaseModel):
    """Model for the result of a threat hunt."""

    log_file: str
    threat_actor: str
    total_iocs_found: int
    detected_iocs: List[DetectedIOC] = []
    message: Optional[str] = None
    error: Optional[str] = None

# --- Industry Intelligence Models ---

class IndustryIntelResult(BaseModel):
    """Model for the result of an industry intelligence analysis."""

    industry: str
    country: Optional[str] = None
    analysis_text: str
    error: Optional[str] = None

class MonopolyAnalysisResult(BaseModel):
    """Model for the result of a monopoly analysis."""

    company_name: str
    industry: str
    analysis_text: str
    error: Optional[str] = None

# --- Aviation Intelligence (AVINT) Models ---

class FlightInfo(BaseModel):
    """Model for a single aircraft's state vector from OpenSky Network."""

    icao24: str
    callsign: str
    origin_country: str
    longitude: Optional[float] = None
    latitude: Optional[float] = None
    baro_altitude: Optional[float] = None
    on_ground: bool
    velocity: Optional[float] = None
    true_track: Optional[float] = None
    vertical_rate: Optional[float] = None
    geo_altitude: Optional[float] = None
    spi: bool
    position_source: int

class AVINTResult(BaseModel):
    """The main, top-level result model for an AVINT scan."""
    
    total_flights: int
    flights: List[FlightInfo] = []
    error: Optional[str] = None


# --- ORM Models ---
class ScanResult(Base): # type: ignore
    """Represents a single scan result from any module."""

    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, index=True, nullable=False)
    module = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    # The result is stored as a JSON string in the database.
    result = Column(Text, nullable=False)


class PageSnapshot(Base): # type: ignore
    """Represents a single snapshot of a monitored web page."""

    __tablename__ = "page_snapshots"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    content_hash = Column(String, nullable=False)
    # Storing the full content allows for detailed diffing later.
    content = Column(LargeBinary, nullable=False)

# --- Humint ---
class HumintScenario(BaseModel):
    """Pydantic model for a HUMINT scenario to be run by the engine."""

    scenario_type: str
    target: str
class HumintSource(Base): # type: ignore
    __tablename__ = "humint_sources"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    reliability = Column(String)  # e.g., 'A1', 'B2'
    expertise = Column(String)
    reports = relationship("HumintReport", back_populates="source")


class HumintReport(Base): # type: ignore
    __tablename__ = "humint_reports"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_id = Column(Integer, ForeignKey("humint_sources.id"))
    source = relationship("HumintSource", back_populates="reports")


class ResponseRule(Base): # type: ignore
    __tablename__ = "response_rules"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    trigger = Column(
        String, nullable=False, index=True
    )  # e.g., "dark-monitor:credential-leak"
    actions = Column(
        JSON, nullable=False
    )  # e.g., ["iam:reset-password", "edr:quarantine-host"]


class ForecastPerformance(Base): # type: ignore
    __tablename__ = "forecast_performance"
    id = Column(Integer, primary_key=True, index=True)
    scenario = Column(String, index=True)
    prediction = Column(Text)  # The AI's generated forecast
    outcome = Column(Text)  # The real-world result, logged later
    is_correct = Column(Boolean)  # Was the prediction accurate?
    timestamp = Column(DateTime, default=datetime.utcnow)

class Token(BaseModel):
    """Model for a JWT access token."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Model for the data encoded in a JWT."""
    username: Optional[str] = None

class DashboardData(BaseModel):
    """Model for the data to be displayed on the main dashboard."""
    total_projects: int
    total_scans: int
    recent_scans: List[Dict[str, Any]] = []

# --- MASINT Core Models ---
class RFEmission(BaseModel):
    """Model for a single detected Radio Frequency emission."""

    frequency_mhz: float
    power_dbm: float
    modulation_type: Optional[str] = None
    source_device_guess: Optional[str] = None
    confidence: str


class AcousticSignature(BaseModel):
    """Model for a single detected acoustic signature."""

    dominant_frequency_hz: float
    decibel_level: float
    signature_type: str  # e.g., "Machinery", "Vehicle", "Power Grid"
    source_object_guess: Optional[str] = None


class ThermalSignature(BaseModel):
    """Model for a single detected thermal signature from multi-spectral imagery."""

    max_temperature_celsius: float
    dominant_infrared_band: str
    activity_level_guess: str  # "Low", "Medium", "High"
    source_object_guess: Optional[str] = None


class MASINTResult(BaseModel):
    """The main, top-level result model for a MASINT analysis."""

    target_identifier: str  # Could be a file path, a coordinate, etc.
    rf_emissions: List[RFEmission] = []
    acoustic_signatures: List[AcousticSignature] = []
    thermal_signatures: List[ThermalSignature] = []
    error: Optional[str] = None

# --- CHEMINT Core Models ---
class ChemInfo(BaseModel):
    """Schema for a single chemical intelligence hit from PubChem/Patents."""
    cid: int = Field(..., description="PubChem Compound ID (CID).")
    iupac_name: Optional[str] = Field(None, description="The IUPAC systematic chemical name.")
    molecular_weight: Optional[float] = Field(None, description="The molecular weight in g/mol.")
    canonical_smiles: Optional[str] = Field(None, description="The Canonical SMILES string (molecular structure).")
    
class PatentInfo(BaseModel):
    """Schema for intelligence gathered from patent and research analysis."""
    patent_id: str
    title: str
    applicant: str
    publication_date: str
    summary: str
    country: str = Field("EP", description="Country code (e.g., US, EP, WO).")

class SDSData(BaseModel):
    """Schema for key data extracted from Safety Data Sheets (or equivalent sources)."""
    cas_number: str
    autoignition_temp_C: Optional[float] = None
    flash_point_C: Optional[float] = None
    nfpa_fire_rating: Optional[int] = Field(None, description="NFPA 704 fire hazard rating (0-4).")
    toxicology_summary: str = Field("N/A", description="A brief summary of health hazards.")

class CHEMINTResult(BaseModel):
    """Container for Chemical Intelligence results."""
    total_results: int
    results: List[ChemInfo | PatentInfo | SDSData]
    error: Optional[str] = None

# --- SPACEINT Core Models ---
class TLEData(BaseModel):
    """Schema for raw Two-Line Element (TLE) data."""
    norad_id: str
    name: Optional[str] = None
    line1: str
    line2: str

class SPACEINTResult(BaseModel):
    """Container for Space Intelligence results."""
    total_satellites: int
    satellites: List[TLEData]
    error: Optional[str] = None

# --- Historical Analysis ---
class HistoricalAnalysisResult(BaseModel):
    """Model for the result of a historical analysis."""

    domain: str
    from_timestamp: Optional[str] = None
    to_timestamp: Optional[str] = None
    diff: Optional[str] = None
    ai_summary: Optional[str] = None
    error: Optional[str] = None

class Node(BaseModel):
    """Model for a single node in an intelligence graph."""

    id: str  # e.g., "megacorp.com", "1.2.3.4"
    type: str  # e.g., "Domain", "IP Address", "Company", "Email"
    label: str
    properties: Dict[str, Any] = {}

class Edge(BaseModel):
    """Model for a relationship (edge) between two nodes in the graph."""

    source: str  # ID of the source node
    target: str  # ID of the target node
    label: str  # e.g., "Resolves To", "Registered By", "Uses Technology"
    properties: Dict[str, Any] = {}

class GraphResult(BaseModel):
    """The main, top-level result model for an entity reconciliation and graph build process."""

    target: str
    total_nodes: int
    total_edges: int
    nodes: List[Node] = []
    edges: List[Edge] = []
    error: Optional[str] = None

class GraphNarrativeResult(BaseModel):
    narrative_text: str
    error: Optional[str] = None

# --- Deep Research ---
class IntelFinding(BaseModel):
    """Represents a single piece of structured intelligence."""
    source_type: str = Field(..., description="The intelligence discipline (e.g., SOCMINT, VULNINT, TECHINT).")
    summary: str = Field(..., description="A concise summary of the key finding.")
    reference: str = Field(..., description="A URL or source reference for verification.")
    risk_level: str = Field(..., description="Assessed risk: Low, Medium, High, or Critical.")
    confidence: str = Field(..., description="Confidence level of the finding: Low, Medium, High.")

class KnowledgeGraph(BaseModel):
    """Represents the constructed knowledge graph of interconnected entities."""
    nodes: List[Dict[str, Any]] = Field(..., description="List of nodes (entities) in the graph.")
    edges: List[Dict[str, Any]] = Field(..., description="List of edges (relationships) connecting the nodes.")

class PESTAnalysis(BaseModel):
    """Represents a Political, Economic, Social, and Technological analysis."""
    political: List[str] = Field(..., description="Political factors affecting the target.")
    economic: List[str] = Field(..., description="Economic factors and trends affecting the target.")
    social: List[str] = Field(..., description="Social and cultural trends relevant to the target.")
    technological: List[str] = Field(..., description="Technological landscape and disruptions affecting the target.")

class DeepResearchResult(BaseModel):
    """The final, structured output of a deep research operation."""
    topic: str
    target_profile: Dict[str, Any]
    strategic_summary: str
    pest_analysis: PESTAnalysis
    intelligence_gaps: List[str]
    recommended_actions: List[str]
    intelligence_findings: List[IntelFinding]
    knowledge_graph: KnowledgeGraph

# --- Economics ---
class EconomicIndicators(BaseModel):
    country: str
    indicators: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

class TrackingUpdate(BaseModel):
    """Details of a single tracking event."""
    status: str
    message: str
    timestamp: str

# --- Logistics ---
class ShipmentDetails(BaseModel):
    """Comprehensive details of a tracked shipment."""
    tracking_code: str
    carrier: str
    status: str
    estimated_delivery_date: Optional[str] = None
    updates: List[TrackingUpdate] = []
    error: Optional[str] = None

# --- Crypto ---
class CryptoData(BaseModel):
    """Represents historical data for a cryptocurrency."""

    symbol: str
    market: str
    history: Optional[Dict[str, Dict[str, str]]] = None
    error: Optional[str] = None
class CryptoForecast(BaseModel):
    """Represents a price forecast for a cryptocurrency."""

    symbol: str
    forecast: Optional[List[float]] = None
    error: Optional[str] = None

# --- Cyber-Physical Systems Intelligence ---
class CyberPhysicalSystemNode(BaseModel):
    """A node in the cyber-physical system graph."""

    id: str
    node_type: str  # e.g., 'PLC', 'SCADA Server', 'Substation', 'GPS Satellite'
    attributes: Dict[str, Any] = {}

class CascadingFailurePath(BaseModel):
    """Represents a potential path of cascading failure."""

    path: List[str]
    description: str


class CPSAnalysisResult(BaseModel):
    """The result of a Cyber-Physical System analysis (without the graph object)."""
    critical_nodes: List[str] = Field(default_factory=list)
    failure_paths: List[CascadingFailurePath] = Field(default_factory=list)
    error: Optional[str] = None

class GeoLocation(BaseModel):
    """Model for a geographic location used in CPS modeling."""

    name: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class SignalIntercept(BaseModel):
    """Model for a single signal intercept observation used in CPS modeling."""

    signal_id: str
    frequency: Optional[float] = None
    timestamp: Optional[str] = None


class Vulnerability(BaseModel):
    """Model for a single system vulnerability, simplifying usage in c_pint.py."""

    cve: str = Field(..., description="The CVE ID or equivalent identifier.")
    cvss_score: Optional[float] = None
    description: Optional[str] = None

# --- Systemic Intelligence ---
class OTAsset(BaseModel):
    device_id: str
    location: str
    vulnerabilities: List[str] = Field(default_factory=list)

class MacroIndicators(BaseModel):
    """Represents key macroeconomic indicators for a country."""

    country: str
    gdp_latest: Optional[float] = Field(
        None, description="Most recent Gross Domestic Product (in current US$)."
    )
    inflation_latest: Optional[float] = Field(
        None, description="Most recent inflation rate (annual %)."
    )
    unemployment_latest: Optional[float] = Field(
        None, description="Most recent unemployment rate (%)."
    )
    error: Optional[str] = None


class MicroIndicators(BaseModel):
    """Represents key microeconomic indicators for a company."""

    symbol: str
    latest_price: Optional[float] = Field(None, description="Latest stock price.")
    market_cap: Optional[str] = Field(
        None, description="Company's market capitalization."
    )
    pe_ratio: Optional[float] = Field(None, description="Price-to-Earnings ratio.")
    error: Optional[str] = None

class SystemNode(BaseModel):
    """A node in the systemic intelligence graph."""
    id: str
    layer: str
    attributes: Dict[str, Any] = Field(default_factory=dict)

class EmergentProperty(BaseModel):
    """Represents an emergent property of the system."""
    property_type: str
    nodes: List[str] = Field(default_factory=list)
    description: str

class SYSINTAnalysisResult(BaseModel):
    """The result of a Systemic Intelligence analysis (without the graph object)."""
    emergent_properties: List[EmergentProperty] = Field(default_factory=list)
    error: Optional[str] = None

# --- Ethical Governance ---
class Target(BaseModel):
    """Represents a structured target for an operation."""
    id: str
    category: str  # e.g., 'network', 'individual', 'infrastructure'
    jurisdiction: Optional[str] = None

class Operation(BaseModel):
    """Represents a proposed operation with structured targets."""
    operation_id: str
    operation_type: str
    is_offensive: bool = False
    targets: List[Target] = Field(default_factory=list)
    targets_eu_citizen: bool = False # Kept for specific GDPR check
    has_legal_basis: bool = False
    justification: Optional[str] = None

class ComplianceViolation(BaseModel):
    """Represents a single rule violation with severity."""
    rule_id: str
    framework: str
    severity: str
    description: str

class ComplianceResult(BaseModel):
    """Holds the result of a compliance audit."""
    operation_id: str
    is_compliant: bool
    violations: List[ComplianceViolation] = Field(default_factory=list)
    audit_log: List[str] = Field(default_factory=list)

# --- Metacognition & Systemic Evolution ---
class OperationLog(BaseModel):
    """Represents a log of a single intelligence-gathering action."""

    module_name: str
    success: bool
    resource_cost: float  # e.g., API credits, CPU time, etc.
    intelligence_tags: List[str] = Field(default_factory=list)


class ModulePerformance(BaseModel):
    """Analyzed performance of a single module."""

    module_name: str
    success_rate: float
    average_cost: float
    efficiency_score: float


class OptimizationRecommendation(BaseModel):
    """A recommendation for optimizing future operations."""

    recommendation: str
    justification: str


class IntelligenceGap(BaseModel):
    """An identified gap in the current intelligence picture."""

    gap_description: str
    generated_collection_requirement: str


class MetacognitionReport(BaseModel):
    """A complete report from the metacognitive analysis."""

    performance_analysis: List[ModulePerformance] = Field(default_factory=list)
    optimizations: List[OptimizationRecommendation] = Field(default_factory=list)
    gaps: List[IntelligenceGap] = Field(default_factory=list)
    error: Optional[str] = None

# --- Dissemination & Actionable Output ---
class IntelligenceFinding(BaseModel):
    """A single finding within an intelligence report."""

    finding_id: str
    description: str
    severity: str  # e.g., 'Low', 'Medium', 'High', 'Critical'
    confidence: float = Field(..., ge=0.0, le=1.0)
    raw_data: Optional[Dict[str, Any]] = None


class IntelligenceReport(BaseModel):
    """A complete, finalized intelligence report."""

    report_id: str
    title: str
    strategic_summary: str
    key_findings: List[IntelligenceFinding] = Field(default_factory=list)

class Task(BaseModel):
    """Represents a single task for a module to execute."""

    id: int
    module: str
    params: Dict[str, Any]
    status: str = "pending"
    result: Optional[Any] = None
    severity: int = 1

# --- Autonomous Intelligence Agent ---

class AnalysisResult(BaseModel):
    """Represents the output from a single intelligence module."""

    module_name: str
    data: Any


class Hypothesis(BaseModel):
    """Represents a hypothesis generated by the reasoning engine."""

    statement: str
    confidence: float


class Recommendation(BaseModel):
    """Represents a recommended course of action."""

    action: str
    priority: str  # e.g., 'Low', 'Medium', 'High'


class ReasoningOutput(BaseModel):
    """The output of the Reasoning Engine's analysis."""

    analytical_summary: str
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    next_steps: List[Dict[str, Any]] = Field(default_factory=list)
class Plan(BaseModel):
    """Represents the sequence of tasks to achieve an objective."""

    objective: str  # Each plan now has its own objective
    tasks: List[Task] = Field(default_factory=list)


class SynthesizedReport(BaseModel):
    """The final, synthesized report for the human analyst."""

    objective: str
    summary: str
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    key_findings: List[str] = Field(default_factory=list)
    raw_outputs: List[Dict[str, Any]] = Field(default_factory=list)

# --- Risk Assessment---
class RiskAssessmentResult(BaseModel):
    """
    Represents the result of a risk assessment.
    """

    asset: str = Field(..., description="The asset at risk.")
    threat: str = Field(..., description="The threat to the asset.")
    probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="The probability of the threat occurring (0.0 to 1.0).",
    )
    impact: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="The impact of the threat if it occurs (0.0 to 10.0).",
    )
    risk_score: float = Field(
        ..., ge=0.0, le=10.0, description="The calculated risk score."
    )
    risk_level: str = Field(
        ..., description="The qualitative risk level (e.g., Low, Medium, High)."
    )
    details: Optional[ThreatIntelResult] = Field(
        None, description="Threat intelligence details."
    )
    vulnerabilities: List[CVE] = Field(  # Changed from Vulnerability to CVE
        [], description="Vulnerabilities associated with the asset."
    )
    threat_actors: List[ThreatActor] = Field(
        [], description="Threat actors associated with the threat."
    )
    mitigation: List[str] = Field([], description="Suggested mitigation actions.")
    error: Optional[str] = Field(
        None, description="Any error that occurred during the assessment."
    )

class CredibilityResult(BaseModel):
    """
    Represents the result of a credibility assessment.
    """

    url: str = Field(..., description="The URL that was assessed.")
    credibility_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="A score from 0 (not credible) to 10 (highly credible).",
    )
    factors: List[str] = Field(
        ..., description="A list of factors that contributed to the score."
    )
    error: Optional[str] = Field(
        None, description="Any error that occurred during the assessment."
    )

# --- Negotiation---
class PartyType(str, Enum):
    COMPANY = "company"
    INDIVIDUAL = "individual"
    GOVERNMENT = "government"
    OTHER = "other"

class Channel(str, Enum):
    EMAIL = "email"
    CHAT = "chat"
    VOICE = "voice"
    MEETING = "meeting"
    CLI = "cli"

# --- Main Data Models ---

class Party(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: PartyType
    industry: Optional[str] = None
    country: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Offer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    negotiation_id: str
    party_id: str
    message_id: Optional[str] = None
    amount_terms: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    accepted: Optional[str] = 'pending'  # pending, accepted, rejected
    accepted_at: Optional[datetime] = None
    currency: Optional[str] = "USD"
    valid_until: Optional[datetime] = None
    confidence_score: Optional[float] = None
    revision: int = 1
    previous_offer_id: Optional[str] = None

class NegotiationStatus(str, Enum):
    ONGOING = "ongoing"
    CLOSED = "closed"
    CANCELLED = "cancelled"

class ChannelType(str, Enum):
    EMAIL = "email"
    CHAT = "chat"
    VOICE = "voice"
    MEETING = "meeting"

class NegotiationParty(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    party_id: str
    name: str
    type: PartyType
    role: str  # e.g., 'buyer', 'seller'

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    negotiation_id: str
    sender_id: str
    content: str
    channel: ChannelType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analysis: Optional[dict]
    tone_score: Optional[float] = None
    sentiment_label: Optional[str] = None
    intent_label: Optional[str] = None
    language: Optional[str] = "en"

    class Config:
        orm_mode = True

class NegotiationModel(Base):
    __tablename__ = "negotiations"

    id = Column(String, primary_key=True, index=True)
    subject = Column(String, index=True)
    status = Column(SQLAlchemyEnum(NegotiationStatus), default=NegotiationStatus.ONGOING)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    messages = relationship("MessageModel", back_populates="negotiation")

class MessageModel(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, index=True)
    negotiation_id = Column(String, ForeignKey("negotiations.id"))
    sender_id = Column(String)
    content = Column(String)
    analysis = Column(JSON) # Store sentiment, intent, etc.
    timestamp = Column(DateTime, default=datetime.utcnow)

    negotiation = relationship("NegotiationModel", back_populates="messages")

class MessageBase(BaseModel):
    sender_id: str
    content: str

class MessageCreate(MessageBase):
    pass

class NegotiationBase(BaseModel):
    subject: str

class Negotiation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    status: NegotiationStatus = NegotiationStatus.ONGOING
    created_by: str
    end_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    participants: List[Party] = Field(default_factory=list)
    messages: List[Message] = []

    class Config:
        orm_mode = True

class SimulationScenario(BaseModel):
    our_min: float
    our_max: float
    their_min: float
    their_max: float

    @validator('our_max')
    def our_max_must_be_greater_than_our_min(cls, v, values, **kwargs):
        if 'our_min' in values and v <= values['our_min']:
            raise ValueError('our_max must be greater than our_min')
        return v

class NegotiationSession(Base):
    __tablename__ = 'negotiation_sessions'
    id = Column(String, primary_key=True)
    subject = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String, default='ongoing')
    outcome = Column(String)
    messages = relationship("Message", back_populates="session")
    offers = relationship("Offer", back_populates="session")
class BehavioralProfile(BaseModel):
    """Model for the behavioral profile of a negotiation party."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    party_id: str
    communication_style: Optional[str] = None # e.g., "Formal", "Informal"
    risk_appetite: Optional[str] = None      # e.g., "Risk-averse", "Risk-seeking"
    key_motivators: List[str] = Field(default_factory=list)

class Counterparty(BaseModel):
    """Model for a counterparty in a negotiation."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    industry: Optional[str] = None
    country: Optional[str] = None
    historical_deals: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_profile: Optional[BehavioralProfile] = None

class MarketIndicator(BaseModel):
    """Model for a relevant market indicator."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    value: float
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class NegotiationParticipant(BaseModel):
    """Represents a single participant in a negotiation session."""
    participant_id: str
    participant_name: str

class Config:
        orm_mode = True

class VoiceAnalysis(BaseModel):
    """Represents the analysis of vocal tone from an audio message."""
    vocal_sentiment: str
    confidence_score: float
    pace: str
    pitch_variation: str


# --- Negotiation & Simulation ---
class NegotiationMessage(BaseModel):
    negotiation_id: str
    sender_id: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analysis: Dict[str, Any]


class LLMLog(BaseModel):
    model_name: str
    prompt: str
    response: str
    ethical_flags: List[str]
    cultural_context: Dict[str, Any]
    state: Dict[str, Any]
    action: int
    reward: float


class RLLog(BaseModel):
    state: Dict[str, Any]
    action: int
    reward: float

class AnalysisResponse(BaseModel):
    message_id: str
    analysis: Dict[str, Any]
    recommended_tactic: Dict[str, str]
    simulation: Dict[str, Any]

class NegotiationParticipantCreate(BaseModel):
    participant_id: str
    participant_name: str

class NegotiationCreate(BaseModel):
    subject: str
    participants: List[NegotiationParticipantCreate]

# --- Application Configuration ---
class IntelSourceConfig(BaseModel):
    enabled: bool = True
    api_key_required: bool = False


class FeatureFlags(BaseModel):
    enable_dark_web_monitoring: bool = Field(
        True, description="Enable continuous monitoring of dark web forums."
    )
    enable_social_media_monitoring: bool = Field(
        True, description="Enable real-time social media listening."
    )

# --- Role Definitions ---
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

# --- User Schemas ---
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: UserRole = UserRole.USER  # Default role for new users

class User(UserBase):
    id: Union[int, str] = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    role: UserRole = UserRole.USER

    class Config:
        orm_mode = True

# --- Application Configuration Schemas ---
class NetworkConfig(BaseModel):
    timeout: float = 20.0

class FootprintModuleConfig(BaseModel):
    dns_records_to_query: List[str] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

class WebAnalyzerModuleConfig(BaseModel):
    placeholder: bool = True

class DarkWebModuleConfig(BaseModel):
    tor_proxy_url: str = "socks5://127.0.0.1:9150"

class MarintModuleConfig(BaseModel):
    placeholder: bool = True

class NegotiationModuleConfig(BaseModel):
    model_path: str = "models/negotiation_intent_model"

class ModulesConfig(BaseModel):
    footprint: FootprintModuleConfig = Field(default_factory=FootprintModuleConfig)
    web_analyzer: WebAnalyzerModuleConfig = Field(default_factory=WebAnalyzerModuleConfig)
    dark_web: DarkWebModuleConfig = Field(default_factory=DarkWebModuleConfig)
    marint: MarintModuleConfig = Field(default_factory=MarintModuleConfig)
    negotiation: NegotiationModuleConfig = Field(default_factory=NegotiationModuleConfig)

class ReportingGraphConfig(BaseModel):
    physics_options: str = Field(
        default="""
      var options = {
        "physics": {
          "barnesHut": {
            "gravitationalConstant": -40000,
            "centralGravity": 0.4,
            "springLength": 180
          },
          "minVelocity": 0.75
        }
      }
    """
    )

class ReportingPdfConfig(BaseModel):
    logo_path: str = "src/chimera_intel/assets/my_logo.png"
    title_text: str = "Chimera Intel - Intelligence Report"
    footer_text: str = "Confidential | Prepared by Chimera Intel"

class ReportingConfig(BaseModel):
    project_report_scans: List[str] = ["footprint", "web_analyzer", "defensive_breaches"]
    graph: ReportingGraphConfig = Field(default_factory=ReportingGraphConfig)
    pdf: ReportingPdfConfig = Field(default_factory=ReportingPdfConfig)

class AppConfig(BaseModel):
    app_name: str = "Chimera Intel"
    version: str = "1.0.0"
    log_level: str = "INFO"
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    intel_sources: Dict[str, IntelSourceConfig] = Field(default_factory=dict)
    feature_flags: FeatureFlags = Field(default_factory=FeatureFlags)
    notifications: ConfigNotifications = ConfigNotifications()
    graph_db: ConfigGraphDB = ConfigGraphDB()


