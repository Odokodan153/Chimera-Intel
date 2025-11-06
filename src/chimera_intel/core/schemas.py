from typing import Any, Dict, List, Optional, Union, HttpUrl
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    SQLModel,
    SQLField,
    Boolean,
    LargeBinary,
    Enum as SQLAlchemyEnum,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, date, timezone
import pandas as pd
import numpy as np
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


class DnssecInfo(BaseModel):
    dnssec_enabled: bool
    spf_record: str
    dmarc_record: str


class TlsCertInfo(BaseModel):
    issuer: str
    subject: str
    sans: List[str]
    not_before: str
    not_after: str


class AsnInfo(BaseModel):
    asn: Optional[str] = None
    owner: Optional[str] = None
    country: Optional[str] = None
    prefix: Optional[str] = None


class HistoricalDns(BaseModel):
    a_records: List[str]
    aaaa_records: List[str]
    mx_records: List[str]


class IpGeolocation(BaseModel):
    ip: str
    city: Optional[str] = None
    country: Optional[str] = None
    provider: Optional[str] = None


class BreachInfo(BaseModel):
    source: str
    breaches: List[str]


class PortScanResult(BaseModel):
    open_ports: Dict[int, str]


class WebTechInfo(BaseModel):
    cms: Optional[str] = None
    framework: Optional[str] = None
    web_server: Optional[str] = None
    js_library: Optional[str] = None


class PersonnelInfo(BaseModel):
    employees: List[Dict[str, str]]


class SocialMediaPresence(BaseModel):
    twitter: Optional[str] = None
    linkedin: Optional[str] = None
    github: Optional[str] = None


class KnowledgeGraph(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class FootprintData(BaseModel):
    whois_info: Dict[str, Any]
    dns_records: Dict[str, Any]
    subdomains: SubdomainReport
    ip_threat_intelligence: List[Any]
    historical_dns: HistoricalDns
    reverse_ip: Dict[str, List[str]]
    asn_info: Dict[str, AsnInfo]
    tls_cert_info: TlsCertInfo
    dnssec_info: DnssecInfo
    ip_geolocation: Dict[str, IpGeolocation]
    cdn_provider: Optional[str] = None
    breach_info: BreachInfo
    port_scan_results: Dict[str, PortScanResult]
    web_technologies: WebTechInfo
    personnel_info: PersonnelInfo
    knowledge_graph: KnowledgeGraph


class FootprintResult(BaseModel):
    """The main, top-level result model for a footprint scan."""

    domain: str
    footprint: FootprintData


class IpInfo(BaseModel):
    asn: AsnInfo
    geolocation: IpGeolocation


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

class SmartContractAnalysis(BaseModel):
    address: str
    is_verified: bool = False
    contract_name: Optional[str] = None
    creator_address: Optional[str] = None
    creator_tx_hash: Optional[str] = None
    token_name: Optional[str] = None
    token_symbol: Optional[str] = None
    source_code_snippet: Optional[str] = None
    error: Optional[str] = None

class TokenFlow(BaseModel):
    hash: str
    from_address: str
    to_address: str
    token_symbol: str
    amount: float
    timestamp: str

class TokenFlowResult(BaseModel):
    address: str
    token_symbol_filter: Optional[str] = None
    token_flows: List[TokenFlow] = Field(default_factory=list)
    total_flows_tracked: int = 0
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
    transactionShares: int
    transactionCode: str
    price: float
    change: int
    value: Optional[int] = None


class InsiderTradingResult(BaseModel):
    """The main, top-level result model for an insider trading scan."""

    stock_symbol: str
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

class StabilityForecastResult(BaseModel):
    """
    Model for the result of a multi-modal stability forecast.
    """
    country: str
    region: Optional[str] = None
    analysis_text: str
    short_term_index: float = 0.0
    long_term_index: float = 0.0
    key_factors: Dict[str, Any] = Field(default_factory=dict)
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
class ScanResult(Base):  # type: ignore
    """Represents a single scan result from any module."""

    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, index=True, nullable=False)
    module = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    # The result is stored as a JSON string in the database.
    result = Column(Text, nullable=False)


class PageSnapshot(Base):  # type: ignore
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


class HumintSource(Base):  # type: ignore
    __tablename__ = "humint_sources"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    reliability = Column(String)  # e.g., 'A1', 'B2'
    expertise = Column(String)
    reports = relationship("HumintReport", back_populates="source")


class HumintReport(Base):  # type: ignore
    __tablename__ = "humint_reports"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_id = Column(Integer, ForeignKey("humint_sources.id"))
    source = relationship("HumintSource", back_populates="reports")


class ResponseRule(Base):  # type: ignore
    __tablename__ = "response_rules"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    trigger = Column(
        String, nullable=False, index=True
    )  # e.g., "dark-monitor:credential-leak"
    actions = Column(
        JSON, nullable=False
    )  # e.g., ["iam:reset-password", "edr:quarantine-host"]


class ForecastPerformance(Base):  # type: ignore
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
    iupac_name: Optional[str] = Field(
        None, description="The IUPAC systematic chemical name."
    )
    molecular_weight: Optional[float] = Field(
        None, description="The molecular weight in g/mol."
    )
    canonical_smiles: Optional[str] = Field(
        None, description="The Canonical SMILES string (molecular structure)."
    )


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
    nfpa_fire_rating: Optional[int] = Field(
        None, description="NFPA 704 fire hazard rating (0-4)."
    )
    toxicology_summary: str = Field(
        "N/A", description="A brief summary of health hazards."
    )


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


# --- Deep Research ---
class IntelFinding(BaseModel):
    """Represents a single piece of structured intelligence."""

    source_type: str = Field(
        ...,
        description="The intelligence discipline (e.g., SOCMINT, VULNINT, TECHINT).",
    )
    summary: str = Field(..., description="A concise summary of the key finding.")
    reference: str = Field(
        ..., description="A URL or source reference for verification."
    )
    risk_level: str = Field(
        ..., description="Assessed risk: Low, Medium, High, or Critical."
    )
    confidence: str = Field(
        ..., description="Confidence level of the finding: Low, Medium, High."
    )


class PESTAnalysis(BaseModel):
    """Represents a Political, Economic, Social, and Technological analysis."""

    political: List[str] = Field(
        ..., description="Political factors affecting the target."
    )
    economic: List[str] = Field(
        ..., description="Economic factors and trends affecting the target."
    )
    social: List[str] = Field(
        ..., description="Social and cultural trends relevant to the target."
    )
    technological: List[str] = Field(
        ..., description="Technological landscape and disruptions affecting the target."
    )


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
    severity: Optional[str] = None


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
    """Represents a target in an operation."""

    id: str
    category: str


class Operation(BaseModel):
    """Defines the structure for an intelligence operation to be audited."""

    operation_id: str
    operation_type: str
    targets: List[Target] = Field(default_factory=list)
    justification: str = ""
    is_offensive: bool = False
    targets_eu_citizen: bool = False
    has_legal_basis: bool = False

    # Allows for extra fields that are not explicitly defined
    class Config:
        extra = "allow"


class ComplianceViolation(BaseModel):
    """Represents a single rule violation."""

    rule_id: str
    framework: str
    severity: str
    description: str


class ComplianceResult(BaseModel):
    """Contains the full result of a compliance audit."""

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
    vulnerabilities: List[Vulnerability] = Field(  # Changed from Vulnerability to CVE
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
    accepted: Optional[str] = "pending"  # pending, accepted, rejected
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


class NegotiationModel(Base):  # type: ignore
    __tablename__ = "negotiations"

    id = Column(String, primary_key=True, index=True)
    subject = Column(String, index=True)
    status = Column(
        SQLAlchemyEnum(NegotiationStatus), default=NegotiationStatus.ONGOING
    )
    created_at = Column(DateTime, default=datetime.utcnow)


class OfferModel(Base):  # type: ignore
    __tablename__ = "offers"

    id = Column(String, primary_key=True, index=True)
    negotiation_id = Column(String, ForeignKey("negotiation_sessions.id"))
    party_id = Column(String)
    amount_terms = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    accepted = Column(String, default="pending")

    session = relationship("NegotiationSession", back_populates="offers")


class MessageModel(Base):  # type: ignore
    __tablename__ = "messages"

    id = Column(String, primary_key=True, index=True)
    negotiation_id = Column(
        String, ForeignKey("negotiation_sessions.id")
    )  # Changed ForeignKey
    sender_id = Column(String)
    content = Column(String)
    analysis = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)


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

    @validator("our_max")
    def our_max_must_be_greater_than_our_min(cls, v, values, **kwargs):
        if "our_min" in values and v <= values["our_min"]:
            raise ValueError("our_max must be greater than our_min")
        return v


class NegotiationSession(Base):  # type: ignore
    __tablename__ = "negotiation_sessions"
    id = Column(String, primary_key=True)
    subject = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String, default="ongoing")
    outcome = Column(String)
    messages = relationship(
        "MessageModel", back_populates="session"
    )  # Corrected relationship
    offers = relationship("OfferModel", back_populates="session")


class BehavioralProfile(BaseModel):
    """Model for the behavioral profile of a negotiation party."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    party_id: str
    communication_style: Optional[str] = None  # e.g., "Formal", "Informal"
    risk_appetite: Optional[str] = None  # e.g., "Risk-averse", "Risk-seeking"
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


class SimulationMode(str, Enum):
    training = "training"
    inference = "inference"


class NegotiationParticipant(Base):  # type: ignore
    __tablename__ = "negotiation_participants"
    session_id = Column(String, ForeignKey("negotiation_sessions.id"), primary_key=True)
    participant_id = Column(String, primary_key=True)
    participant_name = Column(String)


# --- Application Configuration ---
class IntelSourceConfig(BaseModel):
    enabled: bool = True
    api_key_required: bool = False


class FeatureFlags(BaseModel):
    """Defines the feature flags for enabling or disabling modules."""

    enable_offensive_modules: bool = True
    enable_defensive_modules: bool = True
    enable_ai_core: bool = True
    enable_mlops_automation: bool = True


# --- Role Definitions ---
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"


# --- User Schemas ---
class UserBase(BaseModel):
    username: str


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
    web_analyzer: WebAnalyzerModuleConfig = Field(
        default_factory=WebAnalyzerModuleConfig
    )
    dark_web: DarkWebModuleConfig = Field(default_factory=DarkWebModuleConfig)
    marint: MarintModuleConfig = Field(default_factory=MarintModuleConfig)
    negotiation: NegotiationModuleConfig = Field(
        default_factory=NegotiationModuleConfig
    )


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
    project_report_scans: List[str] = [
        "footprint",
        "web_analyzer",
        "defensive_breaches",
    ]
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
    notifications: ConfigNotifications = Field(default_factory=ConfigNotifications)
    graph_db: ConfigGraphDB = Field(default_factory=ConfigGraphDB)


class User(BaseModel):
    """User model for authentication and context."""

    id: Optional[int] = None
    username: str
    email: EmailStr
    hashed_password: str

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    """Schema for creating a new user."""

    username: str
    email: EmailStr
    password: str


class Event:
    """Represents a security event."""

    def __init__(self, event_type: str, source: str, details: Dict[str, Any]):
        self.id = ""
        self.event_type = event_type
        self.source = source
        self.details = details


class WhoisInfo(BaseModel):
    """A model for WHOIS information."""

    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    name_servers: List[str] = []


class PageMonitorResult(BaseModel):
    """Model for the result of a page monitor check."""

    target: str
    url: str
    has_changed: bool
    diff: Optional[str] = None


class InsiderTransactionResult(BaseModel):
    """The main, top-level result model for an insider trading scan."""

    stock_symbol: str = ""
    total_transactions: int = 0
    transactions: List[InsiderTransaction] = []
    error: Optional[str] = None


class TwitterStreamResult(BaseModel):
    """The main, top-level result model for a real-time social media monitoring session."""

    query: str
    total_tweets_found: int = 0
    tweets: List[Tweet] = []
    error: Optional[str] = None

# ---  MLINT Schemas ---

class BaseResult(BaseModel):
    error: Optional[str] = None

class JurisdictionRisk(BaseModel):
    country: str
    risk_level: str = "Low"
    is_fatf_grey_list: bool = False
    is_fatf_black_list: bool = False
    risk_score: int = 0
    details: str

class EntityRiskResult(BaseResult):
    company_name: str
    jurisdiction: str
    risk_score: int = Field(default=0, description="Composite risk score (0-100)")
    risk_factors: List[str] = Field(default_factory=list, description="Explainable reasons for the score")
    pep_links: int = Field(default=0, description="Number of linked Politically Exposed Persons")
    adverse_media_hits: int = Field(default=0, description="Number of negative news articles")
    shell_company_indicators: List[str] = Field(default_factory=list)
    sanctions_hits: int = Field(default=0, description="Number of direct hits on sanctions lists")

class CryptoWalletScreenResult(BaseResult):
    wallet_address: str
    risk_level: str = "Low"
    risk_score: int = Field(default=0, description="Risk score (0-100)")
    known_associations: List[str] = Field(default_factory=list, description="e.g., Known Exchange, Darknet Market")
    mixer_interaction: bool = Field(default=False, description="Has interacted with a known mixer/tumbler")
    sanctioned_entity_link: bool = Field(default=False, description="Linked to a sanctioned entity's wallet")
    
class Transaction(BaseModel):
    id: str
    date: date
    amount: float
    currency: str
    sender_id: str
    receiver_id: str
    sender_jurisdiction: Optional[str] = None
    receiver_jurisdiction: Optional[str] = None

class TransactionAnalysisResult(BaseResult):
    total_transactions: int
    total_volume: float
    structuring_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    round_tripping_alerts: List[List[str]] = Field(default_factory=list)
    high_risk_jurisdiction_flows: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_score: float = Field(default=0.0, description="ML-based anomaly score (e.g., from Isolation Forest)")
    anomaly_features_used: List[str] = Field(default_factory=list)

class SwiftTransactionAnalysisResult(BaseResult):
    file_name: str
    message_type: str = "MT103"
    sender_bic: Optional[str] = None
    receiver_bic: Optional[str] = None
    mur_code: Optional[str] = None
    transaction: Optional[Transaction] = None
    analysis: Optional[TransactionAnalysisResult] = None


# --- NEW Schemas (from latest proposal) ---

class UboData(BaseModel):
    """Represents a single Ultimate Beneficial Owner."""
    name: str
    ownership_percentage: float
    is_pep: bool = False
    details: str = "Direct Owner"
    address: Optional[str] = None
    nationality: Optional[str] = None

class UboData(BaseModel):
    """Represents a single Ultimate Beneficial Owner."""
    name: str
    ownership_percentage: float
    is_pep: bool = False
    details: str = "Direct Owner"
    address: Optional[str] = None
    nationality: Optional[str] = None

class UboResult(BaseResult):
    """The result of a UBO investigation for a company."""
    company_name: str
    ultimate_beneficial_owners: List[UboData] = Field(default_factory=list)
    corporate_structure: Dict[str, Any] = Field(default_factory=dict, description="Graph-like structure of parent/subsidiary companies")

class WalletCluster(BaseModel):
    """Represents a cluster of crypto wallets controlled by a single entity."""
    main_address: str
    cluster_id: str
    addresses: List[str]
    entity_name: Optional[str] = Field(None, description="Name of the entity, e.g., 'Binance Hot Wallet 7'")
    confidence: float = Field(0.0, description="Confidence score for the cluster attribution")
    category: Optional[str] = Field(None, description="e.g., 'Exchange', 'Darknet Market', 'Scam'")

class WalletClusterResult(BaseResult):
    """The result of a wallet clustering query."""
    wallet_address: str
    cluster: Optional[WalletCluster] = None

class GnnAnomalyResult(BaseResult):
    """The result of a Graph Neural Network anomaly detection model."""
    entity_id: str # Can be a wallet address, account ID, or company ID
    anomaly_score: float
    reason: List[str] = Field(default_factory=list, description="Features contributing to the anomaly (e.g., high centrality, risky counterparties)")
    graph_neighbors: List[str] = Field(default_factory=list, description="IDs of neighbors that influenced this score")

class StreamingAlert(BaseResult):
    """A real-time alert generated from the Kafka stream."""
    timestamp: str
    transaction_id: str
    alert_type: str # e.g., "Structuring", "GNN_Anomaly", "Sanctions_Hit", "Typology_Layering"
    risk_score: int
    summary: str
    related_entities: List[str] = Field(default_factory=list)
    stix_bundle: Optional[Dict[str, Any]] = Field(None, description="Embedded STIX 2.1 bundle for the alert")

class AdverseMediaResult(BaseResult):
    """Result from NLP analysis of adverse media feeds."""
    entity_name: str
    articles_found: int = 0
    negative_sentiment_score: float = Field(0.0, description="Average negative sentiment (0.0 to 1.0)")
    key_themes: List[str] = Field(default_factory=list, description="e.g., 'Fraud', 'Sanctions', 'Bribery'")

class GenerativeSummaryResult(BaseResult):
    """A GenAI-generated summary for an alert or entity."""
    entity_id: str
    summary_text: str
    confidence: float
    sources_consulted: List[str]

class ScenarioSimulationResult(BaseResult):
    """Result of a hypothetical laundering path simulation."""
    scenario_name: str
    path_found: bool
    path: List[str] = Field(default_factory=list)
    weakest_link_node: Optional[str] = None
    vulnerability_exploited: Optional[str] = None

# --- Data Forensics ---

class ForensicArtifactResult(BaseModel):
    file_path: str
    media_type: str = "Image"
    artifacts_found: List[str] = Field(default_factory=list)
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    error: Optional[str] = None

class DeepfakeAnalysisResult(BaseModel):
    file_path: str
    media_type: str = "Video"
    is_deepfake: bool = False
    confidence: float = 0.0
    inconsistencies: List[str] = Field(default_factory=list)
    error: Optional[str] = None

class ProvenanceResult(BaseModel):
    file_path: str
    has_c2pa_credentials: bool = False
    is_valid: bool = False
    issuer: Optional[str] = None
    manifest_history: List[Dict] = Field(default_factory=list)
    error: Optional[str] = None

class NarrativeMapResult(BaseModel):
    topic: str
    key_narratives: List[str] = Field(default_factory=list)
    origin_nodes: List[str] = Field(default_factory=list)
    spread_velocity: float = 0.0
    error: Optional[str] = None

class PoisoningDetectionResult(BaseModel):
    source_url: str
    is_compromised: bool = False
    indicators: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    error: Optional[str] = None

# --- Data Fusion (4D Analysis) Models ---


class MasterEntityProfile(BaseModel):
    """
    A single, resolved "Master Entity Profile" stitched together
    from multiple data fragments.
    """

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    primary_name: Optional[str] = None
    aliases: List[str] = []
    
    # Fused Cyber & Physical Indicators
    linked_cyber_indicators: List[str] = Field(
        default_factory=list,
        description="IPs, domains, emails, usernames, wallet addresses",
    )
    linked_physical_locations: List[PhysicalLocation] = Field(
        default_factory=list
    )
    linked_social_profiles: List[SocialProfile] = Field(default_factory=list)
    
    resolved_from_fragments: List[str] = Field(
        default_factory=list,
        description="Source data points, e.g., 'dark web user:x', 'IP:1.2.3.4'",
    )


class PatternOfLifeEvent(BaseModel):
    """A single, time-stamped event in a target's pattern of life."""

    timestamp: datetime
    event_type: str = Field(
        ..., description="e.g., 'GEOINT', 'AVINT', 'SOCMINT', 'CYBINT'"
    )
    summary: str
    source_data: Dict[str, Any] = Field(
        default_factory=dict, description="Link to the raw source object if possible"
    )
    location: Optional[PhysicalLocation] = None


class PatternOfLife(BaseModel):
    """A 4D (Spatial + Temporal) tracking of a target's life patterns."""

    total_events: int
    events: List[PatternOfLifeEvent]
    ai_summary: str = Field(
        ...,
        description="AI-generated summary of the target's pattern of life.",
    )


class CognitivePrediction(BaseModel):
    """
    A single predictive or prescriptive insight generated
    by the cognitive modeling engine.
    """

    prediction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    prediction_text: str = Field(
        ..., description="What is likely to happen and why."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in the prediction (0.0 to 1.0)"
    )
    justification: str = Field(
        ..., description="The data points that led to this conclusion."
    )
    tactic: str = Field(
        ..., description="The MITRE ATT&CK tactic or intelligence category."
    )


class DataFusionResult(BaseModel):
    """
    The main, top-level result model for a Multi-Modal Data Fusion (4D Analysis) scan.
    """

    target_identifier: str = Field(
        ..., description="The initial target query (e.g., name, username, IP)."
    )
    master_entity_profile: Optional[MasterEntityProfile] = None
    pattern_of_life: Optional[PatternOfLife] = None
    predictions: List[CognitivePrediction] = Field(default_factory=list)
    error: Optional[str] = None

class InfraPattern(BaseModel):
    """A matched infrastructure pattern."""
    pattern_name: str = Field(..., description="Name of the matched APT/TA methodology.")
    provider: str = Field(..., description="Provider (e.g., 'DigitalOcean', 'Namecheap').")
    indicator: str = Field(..., description="The specific indicator (e.g., IP, domain, ASN).")
    confidence: float = Field(..., description="Confidence of the match (0.0 to 1.0).")
    details: Dict[str, Any] = Field(default_factory=dict, description="Raw data from the source, e.g., Shodan banner.")

class InfraSearchResult(BaseModel):
    """Result of a collection infrastructure scan."""
    client_asset: str
    total_found: int = 0
    matched_patterns: List[InfraPattern] = []
    error: Optional[str] = None

class PersonnelRiskScore(BaseModel):
    """Insider threat risk score for a single individual."""
    personnel_id: str = Field(..., description="An identifier for the personnel.")
    risk_score: float = Field(..., description="Calculated risk score (0.0 to 1.0).")
    key_factors: List[str] = Field(..., description="Primary factors contributing to the score.")
    
class InsiderThreatResult(BaseModel):
    """Result of an insider threat scoring analysis."""
    total_personnel_analyzed: int
    high_risk_count: int = 0
    personnel_scores: List[PersonnelRiskScore] = []
    error: Optional[str] = None

class MediaVector(BaseModel):
    """An identified origin or spread vector for media."""
    platform: str = Field(..., description="The platform (e.g., 'Twitter', 'FringeForumX').")
    identifier: str = Field(..., description="The post, user, or article ID/URL.")
    timestamp: Optional[datetime.datetime] = Field(None, description="Timestamp of the post.")
    is_origin: bool = False
    snippet: str

class MediaProvenanceResult(BaseModel):
    """Result of a media manipulation tracking scan."""
    media_fingerprint: str
    media_type: str = "unknown"
    origin_vector: Optional[MediaVector] = None
    spread_path: List[MediaVector] = []
    confidence: float = 0.0
    error: Optional[str] = None

class AttributionScoreResult(BaseModel):
    """Result of an attribution confidence score calculation."""
    proposed_actor: str
    confidence_score: float = Field(..., description="The quantifiable score from 0.0 to 1.0.")
    total_indicators_provided: int
    matched_indicators: List[Dict[str, Any]]
    conflicting_indicators: List[Dict[str, Any]]
    unknown_indicators: List[Dict[str, Any]]
    error: Optional[str] = None

# --- Movememtn Intelligence ---
class FusedLocationPoint(BaseModel):
    source: str
    latitude: float
    longitude: float
    timestamp: str
    velocity: Optional[float] = None
    altitude: Optional[float] = None
    description: str


class MovingTargetResult(BaseModel):
    target_identifier: str
    current_location: Optional[FusedLocationPoint] = None
    historical_track: List[FusedLocationPoint] = []
    error: Optional[str] = None

class InfluenceMapResult(BaseModel):
    """
    Model for the result of a graph-based influence mapping analysis.
    """
    target_space: str
    geography: Optional[str] = None
    influence_scores: Dict[str, float] = Field(default_factory=dict)
    analysis_text: str
    error: Optional[str] = None

class TradeFlowPeriod(BaseModel):
    """
    Represents a single data point in a trade flow time-series.
    """
    period: int
    value_usd: float
    rolling_mean: Optional[float] = None
    rolling_std: Optional[float] = None
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    z_score: Optional[float] = None

    class Config:
        # This allows NaN values (which pandas creates) to be handled gracefully
        # without Pydantic throwing an error. They will be set to None.
        orm_mode = True 
        validate_assignment = True

    @validator('rolling_mean', 'rolling_std', 'baseline_mean', 'baseline_std', 'z_score', pre=True)
    def replace_nan_with_none(cls, v):
        """Replace pandas.NA, numpy.nan, or math.nan with None."""
        try:
            if v is None or pd.isna(v) or np.isnan(v):
                return None
        except (TypeError, ValueError):
            pass # Handle non-numeric types if any, though these fields should be numeric
        return v

class TradeFlowAnomalyResult(BaseModel):
    """
    Model for the result of a trade flow anomaly detection scan.
    """
    commodity_code: str
    country_code: str
    latest_period: Optional[TradeFlowPeriod] = None
    anomalies_detected: List[TradeFlowPeriod] = []
    analysis: Optional[str] = None
    error: Optional[str] = None
class DroneActivityInfo(BaseModel):
    """
    Model for a single detected drone or UAS.
    """
    hex: str
    lat: float
    lon: float
    altitude_ft: int
    speed_kts: int
    track: int
    registration: Optional[str] = None
    aircraft_type: Optional[str] = None
    anomaly: Optional[str] = None

class DroneActivityResult(BaseModel):
    """
    The main, top-level result model for a drone monitoring scan.
    """
    location: Dict[str, Any] # e.g., {"lat": 40.7, "lon": -74.0, "radius_km": 5.0}
    total_drones: int
    drones: List[DroneActivityInfo] = []
    error: Optional[str] = None

class PassiveDNSRecord(BaseModel):
    """Model for a single passive DNS record."""
    hostname: str
    record_type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source: str

class PassiveDNSResult(BaseModel):
    """Model for the result of a passive-dns-query."""
    query_indicator: str
    total_records: int
    records: List[PassiveDNSRecord] = []
    error: Optional[str] = None

class SourcePoisoningIndicator(BaseModel):
    """An indicator of potential data poisoning."""
    indicator_type: str = Field(..., description="e.g., 'Malicious Host', 'Known Disinfo Source', 'Suspicious String'")
    indicator_value: str
    description: str
    confidence: float = Field(..., ge=0.0, le=1.0)

class SourcePoisoningResult(BaseModel):
    """Model for the result of a source-poisoning-detect scan."""
    source_query: str
    is_poisoned: bool
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    indicators: List[SourcePoisoningIndicator] = []
    error: Optional[str] = None

class OpsecScoreFactor(BaseModel):
    """A single factor contributing to an adversary's OPSEC score."""
    factor: str
    description: str
    score_impact: float = Field(..., description="The positive or negative impact on the 0.0-1.0 score (e.g., -0.3)")

class AdversaryOpsecScoreResult(BaseModel):
    """Model for the result of an adversary-opsec-score scan."""
    adversary_identifier: str
    opsec_score: float = Field(..., ge=0.0, le=1.0, description="OPSEC score (0.0=Bad, 1.0=Excellent)")
    summary: str
    factors: List[OpsecScoreFactor] = []
    error: Optional[str] = None

class SyntheticMediaAuditResult(BaseModel):
    """
    Result model for a synthetic-media-audit.
    Categorizes and scores the AI-generation origin.
    """
    file_path: str
    media_type: str
    is_synthetic: bool = False
    confidence: float = Field(..., ge=0.0, le=1.0)
    suspected_origin_model: str = "Unknown"
    analysis_details: Dict[str, Any] = Field(default_factory=dict, description="Aggregated findings from other media modules.")
class SyntheticMediaAuditResult(BaseModel):
    """
    Result model for a synthetic-media-audit.
    Categorizes and scores the AI-generation origin.
    """
    file_path: str
    media_type: str
    is_synthetic: bool = False
    confidence: float = Field(..., ge=0.0, le=1.0)
    suspected_origin_model: str = "Unknown"
    analysis_details: Dict[str, Any] = Field(default_factory=dict, description="Aggregated findings from other media modules.")
    error: Optional[str] = None

# --- ADDED: Schemas for new functionality ---


# Schemas for Internal: disk-artifact-extractor
class DigitalArtifact(BaseModel):
    artifact_type: str = Field(..., description="Type of artifact (e.g., 'Prefetch', 'Shellbag', 'ShimCache').")
    source_path: str = Field(..., description="Path to the artifact within the disk image.")
    extracted_to: Optional[str] = Field(None, description="Path where the artifact was extracted on the host.")
    details: Dict[str, Any] = Field(default_factory=dict, description="Parsed metadata from the artifact.")


class ArtifactExtractionResult(BaseModel):
    image_path: str = Field(..., description="Path to the disk image that was analyzed.")
    artifacts_found: List[DigitalArtifact] = Field(default_factory=list, description="List of extracted artifacts.")
    total_extracted: int = Field(0, description="Total number of artifacts extracted.")
    error: Optional[str] = Field(None, description="Error message if extraction failed.")


# Schema for AppInt: deep-metadata-parser
class DeepMetadata(BaseModel):
    file_path: str = Field(..., description="Path to the file that was analyzed.")
    file_type: str = Field(..., description="Detected file type (e.g., 'AutoCAD DXF', 'Shapefile').")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extracted non-standard metadata.")
    error: Optional[str] = Field(None, description="Error message if extraction failed.")


# Schema for Project: judicial-hold
class JudicialHoldResult(BaseModel):
    project_name: str = Field(..., description="The name of the project.")
    hold_set: bool = Field(False, description="Whether the hold was successfully applied.")
    reason: str = Field(..., description="The reason for the legal hold.")
    set_by_user: str = Field(..., description="The user who set the hold.")
    timestamp: str = Field(..., description="The ISO 8601 timestamp for when the hold was set.")
    snapshot_details: Optional[str] = Field(None, description="Details of the snapshot taken, e.g., 'Copied 125 scans to archive'.")
    error: Optional[str] = Field(None, description="Error message if setting the hold failed.")

# Schemas for Auto: data-quality-governance
class DataFeedStatus(BaseModel):
    feed_name: str = Field(..., description="Name of the data feed (e.g., 'OTX API', 'Vulners API').")
    status: str = Field(..., description="Status of the feed ('UP', 'DOWN', 'DEGRADED').")
    last_checked: str = Field(..., description="ISO 8601 timestamp of the check.")
    message: Optional[str] = Field(None, description="Additional details (e.g., error message, latency, schema validation failure).")

class DataQualityReport(BaseModel):
    feeds_checked: int = Field(0, description="Total number of feeds checked.")
    feeds_down: int = Field(0, description="Number of feeds currently down or degraded.")
    statuses: List[DataFeedStatus] = Field(default_factory=list, description="List of statuses for each feed.")

class ChainOfCustody(BaseModel):
    """Model for a cryptographic hash and timestamp to ensure data integrity."""
    data_hash: str = Field(..., description="Cryptographic hash (e.g., SHA-256) of the raw data.")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="ISO 8601 timestamp of when the data was collected.")
    source_description: str = Field(..., description="Description of the data source (e.g., 'OTX Pulse 123', 'Nmap scan of 1.2.3.4').")

class EvidentiaryReport(BaseModel):
    """Model for a report that includes chain of custody information for legal defensibility."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    evidence_items: List[ChainOfCustody] = Field(default_factory=list)
    report_hash: Optional[str] = Field(None, description="A final hash of all evidence hashes to 'seal' the report.")

# --- Collaboration Schemas (Report:collaborate) ---

class TaskStatus(str, Enum):
    """Enumeration for the status of an investigative task."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"

class InvestigativeTask(Base):  # type: ignore
    """ORM Model for a task assigned to a user within a project."""
    __tablename__ = "investigative_tasks"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), index=True, nullable=False)
    assigned_to_user_id = Column(String, ForeignKey("users.id"), index=True, nullable=True)
    created_by_user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SQLAlchemyEnum(TaskStatus), default=TaskStatus.PENDING, nullable=False)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Annotation(Base):  # type: ignore
    """ORM Model for a user's annotation on a piece of data (e.g., a scan result)."""
    __tablename__ = "annotations"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), index=True, nullable=True)
    target_entity = Column(String, index=True, nullable=True, description="e.g., an IP, domain, or other indicator")
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# --- Data Verification Schemas (Internal:data-verification) ---

class CRAAPScore(BaseModel):
    """A model for a CRAAP (Currency, Relevance, Authority, Accuracy, Purpose) score."""
    currency: float = Field(..., ge=0.0, le=5.0, description="Score for how current the information is.")
    relevance: float = Field(..., ge=0.0, le=5.0, description="Score for how relevant the information is.")
    authority: float = Field(..., ge=0.0, le=5.0, description="Score for the authority of the source.")
    accuracy: float = Field(..., ge=0.0, le=5.0, description="Score for the accuracy and correctness of the information.")
    purpose: float = Field(..., ge=0.0, le=5.0, description="Score for the purpose (e.g., bias) of the information.")
    overall_score: float = Field(..., ge=0.0, le=5.0, description="The averaged final score (0-5 scale).")

class DataVerificationResult(BaseResult):
    """Model for the result of a data verification/reliability check."""
    source_identifier: str = Field(..., description="The feed or data source being scored (e.g., 'otx.alienvault.com', 'Local Scan').")
    reliability_score: float = Field(..., ge=0.0, le=100.0, description="Overall reliability score (0-100).")
    craap_assessment: Optional[CRAAPScore] = Field(None, description="Optional detailed CRAAP breakdown.")
    last_verified: datetime = Field(default_factory=datetime.utcnow)

# --- Custom API Builder Schemas (Internal:custom-API-builder) ---

class CustomAPISource(Base): # type: ignore
    """
    ORM Model for a user-defined custom API data source (low-code tool).
    """
    __tablename__ = "custom_api_sources"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    api_endpoint_url = Column(String, nullable=False, description="The URL, with {target} as a placeholder.")
    http_method = Column(String, default="GET", nullable=False, description="e.g., GET, POST")
    request_params = Column(JSON, nullable=True, description="Key-value pairs for URL params or JSON body. Use {target} as placeholder.")
    request_headers = Column(JSON, nullable=True, description="Key-value pairs for headers. Use {target} as placeholder.")
    data_extraction_path = Column(String, nullable=True, description="JMESPath/JSONPath string to extract relevant data from the response.")
    created_by_user_id = Column(String, ForeignKey("users.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class CustomAPIResult(BaseResult):
    """Model for the result of a scan using a CustomAPISource."""
    source_name: str
    raw_response: Dict[str, Any]
    extracted_data: Optional[Any] = None

class PIIFinding(BaseModel):
    """Model for a single piece of PII found during a compliance check."""
    data_field: str = Field(..., description="The field or key where PII was found.")
    data_snippet: str = Field(..., description="A redacted snippet of the PII.")
    pii_type: str = Field(..., description="The type of PII (e.g., 'Email', 'Phone', 'Name').")
    status: str = Field("Redacted", description="Action taken: 'Redacted' or 'Anonymized'.")

class ComplianceCheckResult(BaseResult):
    """Model for the result of a real-time compliance check for PII/regulatory requirements."""
    module: str = Field(..., description="The module or data source being checked.")
    total_items_scanned: int = 0
    total_findings: int = 0
    findings: List[PIIFinding] = Field(default_factory=list)
    regulatory_frameworks: List[str] = Field(default_factory=list, description="e.g., 'GDPR', 'CCPA'.")
    message: str = "Compliance check complete. PII has been redacted."

class PrivacyImpactReport(BaseResult):
    """Model for a privacy impact report on gathered intelligence."""
    target: str = Field(..., description="The person or group being assessed.")
    summary: str = Field(..., description="AI-generated summary of the privacy impact.")
    data_collected: List[str] = Field(default_factory=list, description="Categories of data collected.")
    potential_risks: List[str] = Field(default_factory=list, description="Potential privacy risks identified.")
    proportionality_assessment: str = Field(..., description="Assessment of whether the data collection is proportionate to the objective.")
    justification: str = Field(..., description="Justification for the investigation.")

class SyntheticTextAnalysis(BaseModel):
    is_synthetic: bool = False
    confidence: float = 0.0
    evidence: str = "No synthetic indicators found."

class SyntheticNarrativeItem(BaseModel):
    source: str
    type: str  # "News" or "Tweet"
    content: str
    sentiment: str
    synthetic_analysis: SyntheticTextAnalysis

class SyntheticNarrativeMapResult(BaseModel):
    query: str
    total_items_found: int
    synthetic_items_detected: int
    synthetic_items_by_type: Dict[str, int] = Field(default_factory=dict)
    synthetic_narrative_map: List[SyntheticNarrativeItem] = Field(default_factory=list)
    error: Optional[str] = None

class VoiceMatch(BaseModel):
    known_adversary_file: str
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    decision: str = "No Match"

class AdversaryVoiceMatchResult(BaseModel):
    new_audio_file: str
    match_threshold: float
    status: str = "Completed"
    matches_found: List[VoiceMatch] = Field(default_factory=list)
    error: Optional[str] = None

class ReputationModelResult(BaseModel):
    query: str
    media_file: str
    media_synthetic_confidence: float = 0.0
    amplification_network_strength: float = 0.0
    projected_impact_score: float = Field(..., ge=0.0, le=10.0)
    risk_level: str = "Low"
    projected_impact_timeline: List[float] = Field(default_factory=list, description="Projected impact score over the next 7 days.")
    error: Optional[str] = None

# --- Multimodal Reasoning Schemas ---

class MultimodalReasoningResult(BaseResult):
    """Result of a multimodal reasoning task."""
    target: str
    cross_correlations: List[str] = []
    fused_insights: List[str] = []


# --- Event Modeling Schemas ---

class EventEntity(BaseModel):
    """An entity involved in an event."""
    name: str
    type: str  # e.g., "person", "location", "asset", "indicator"

class Event(BaseModel):
    """A single reconstructed event in a timeline."""
    timestamp: str
    event_description: str
    entities: List[EventEntity] = []
    source_report_hint: str # A quote or hint from the source data

class EventModelingResult(BaseResult):
    """Result of an event modeling task."""
    target: str
    timeline: List[Event] = []
    total_events: int = 0


# --- Sentiment Time Series Schemas ---

class SentimentDataPoint(BaseModel):
    """A single point in a sentiment time series."""
    timestamp: str
    sentiment_score: float  # -1.0 to 1.0
    emotional_tone: str     # e.g., "Neutral", "Anger", "Joy"
    document_hint: str      # A snippet of the source document

class SentimentAnomaly(BaseModel):
    """A detected anomaly in a sentiment time series."""
    timestamp: str
    document_hint: Optional[str] = None
    shift_direction: str  # "Positive" or "Negative"
    shift_magnitude: float
    message: str

class SentimentTimeSeriesResult(BaseResult):
    """Result of a sentiment time series analysis."""
    target: str
    time_series: List[SentimentDataPoint] = []
    anomalies: List[SentimentAnomaly] = []
    overall_average_sentiment: float = 0.0
    total_documents_analyzed: int = 0
    total_errors: int = 0


# --- Bias Audit Schemas ---

class BiasFinding(BaseModel):
    """A single potential bias detected in a report."""
    bias_type: str  # e.g., "Confirmation Bias", "Collection Gap"
    evidence: str
    recommendation: str

class BiasAuditResult(BaseResult):
    """Result of a bias audit on a report."""
    report_identifier: str  # The name/path of the report that was audited
    findings: List[BiasFinding] = []
    total_findings: int = 0

# --- Schemas for Supply Chain Risk ---

class SoftwareComponent(BaseModel):
    """Represents a single software component or dependency."""
    name: str
    version: str
    supplier: Optional[str] = None
    ecosystem: Optional[str] = "pypi"  # e.g., pypi, npm, maven

class SupplyChainVulnerability(BaseModel):
    """Details of a vulnerability found in a component."""
    cve_id: str
    severity: str  # e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str
    component_name: str
    component_version: str

class SupplyChainRiskResult(BaseModel):
    """The result of a supply chain risk analysis."""
    target_components: List[SoftwareComponent]
    found_vulnerabilities: List[SupplyChainVulnerability] = []
    risk_score: float = Field(default=0.0, description="Calculated risk score from 0.0 to 10.0")
    summary: Optional[str] = None
    error: Optional[str] = None

# --- Schemas for Malware Sandbox ---

class SandboxFile(BaseModel):
    """Details of the file submitted to the sandbox."""
    filename: Optional[str] = None
    file_hash: str = Field(..., description="SHA256 hash of the file")
    file_type: Optional[str] = None

class SandboxBehavior(BaseModel):
    """A notable behavior observed during sandbox execution."""
    category: str  # e.g., "network", "filesystem", "registry"
    description: str
    mitre_ttp_id: Optional[str] = None
    risk_level: str = "INFO" # e.g., "SUSPICIOUS", "MALICIOUS", "INFO"

class SandboxResult(BaseModel):
    """The result of an automated malware sandbox analysis."""
    file_details: SandboxFile
    is_malicious: bool = False
    malware_family: Optional[str] = None
    confidence_score: float = Field(default=0.0, description="Confidence in the verdict (0.0 to 1.0)")
    observed_behaviors: List[SandboxBehavior] = []
    error: Optional[str] = None

# --- Schemas for Zero-Day Tracking ---

class EmergingExploit(BaseModel):
    """Information about a newly discovered exploit or zero-day."""
    exploit_id: str = Field(..., description="A unique ID, e.g., CVE-202X-XXXX or a vendor ID")
    product: str
    vendor: str
    description: str
    source_url: str
    discovered_on: str # ISO date string
    is_zero_day: bool = Field(default=False, description="True if no patch is available")

class ZeroDayTrackingResult(BaseModel):
    """The result of monitoring for emerging exploits."""
    query: str  # The product, vendor, or topic being monitored
    emerging_exploits: List[EmergingExploit] = []
    summary: Optional[str] = None
    error: Optional[str] = None


class TopicCluster(BaseModel):
    cluster_id: int
    cluster_name: str = Field(
        ..., description="A concise, descriptive name for the topic cluster."
    )
    document_indices: List[int] = Field(
        ..., description="List of zero-based indices of documents in this cluster."
    )
    document_hints: List[str] = Field(
        ..., description="A list of snippets from documents in this cluster."
    )
    document_count: int


class TopicClusteringResult(BaseModel):
    total_documents_analyzed: int
    total_clusters_found: int
    clusters: List[TopicCluster]
    unclustered_documents: int = 0
    error: Optional[str] = None

class ChainOfCustodyEntry(BaseModel):
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    action: str
    actor: str = "chimera-intel-system"
    details: str

class AuditableDataReceipt(BaseModel):
    receipt_id: str
    target: str
    source: str
    content_sha256: str
    ingest_timestamp: str
    judicial_hold: bool = False
    judicial_hold_reason: Optional[str] = None
    chain_of_custody: list[ChainOfCustodyEntry] = []

class PrivacyImpactReport(BaseModel):
    report_id: str
    target: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_documents_scanned: int
    documents_with_pii: int
    overall_risk_level: str  # e.g., "Low", "Medium", "High", "Critical"
    violation_summary: Dict[str, int] = Field(
        description="A summary count of PII types found, e.g., {'EMAIL': 5, 'PHONE': 2}"
    )
    mitigation_steps: List[str]
    violations: List[Dict[str, Any]] = Field(
         description="A list of specific violation details."
    )

class BuildingFootprint(BaseModel):
    """
    Represents a building footprint from OpenStreetMap.
    """
    osm_id: int = Field(..., description="OpenStreetMap element ID.")
    type: str = Field(..., description="Element type (e.g., 'way').")
    tags: Dict[str, str] = Field(..., description="OSM tags for the building.")
    geometry: List[Dict[str, float]] = Field(..., description="List of (lat, lon) coordinates defining the building's geometry.")

class FacilityMapResult(BaseModel):
    """
    Combined result for facility mapping.
    """
    query: str
    locations_found: List[PhysicalLocation] = Field(default_factory=list)
    building_footprints: List[BuildingFootprint] = Field(default_factory=list)
    logistics_route: Optional[Dict[str, Any]] = Field(None, description="Simplified directions summary from Google Maps.")
    error: Optional[str] = None

class PhysicalEvent(BaseModel):
    """
    Represents a detected physical event (e.g., protest, strike).
    """
    title: str
    source_name: str
    url: str
    timestamp: Optional[str]
    location: Optional[str] = None
    summary: Optional[str] = None

class EventDetectionResult(BaseModel):
    """
    Result for a physical event monitoring query.
    """
    query: str
    events_found: List[PhysicalEvent] = Field(default_factory=list)
    total_events: int = 0
    error: Optional[str] = None

class AerialVehicleInfo(BaseModel):
    """
    Information about a detected aerial vehicle.
    """
    hex: str = Field(..., description="ICAO hex identifier.")
    flight: str = Field(None, description="Flight number or callsign.")
    lat: float = Field(..., description="Current latitude.")
    lon: float = Field(..., description="Current longitude.")
    altitude_ft: int = Field(None, description="Altitude in feet.")
    speed_kts: int = Field(None, description="Speed in knots.")
    track_deg: int = Field(None, description="Heading in degrees.")
    vehicle_type: str = Field(None, description="Aircraft type description.")

class AerialIntelResult(BaseModel):
    """
    Result for an aerial intelligence scan.
    """
    query_lat: float
    query_lon: float
    query_radius_km: int
    vehicles_found: List[AerialVehicleInfo] = Field(default_factory=list)
    total_vehicles: int = 0
    error: Optional[str] = None

class WorldBankIndicator(BaseModel):
    """Represents a single data point from the World Bank API."""
    indicator: str
    country: str
    country_iso3: str = Field(..., alias="countryiso3code")
    date: str
    value: Optional[float]
    unit: str
    source_id: str = Field(..., alias="sourceID")
    last_updated: str = Field(..., alias="lastupdated")

class OpenDataResult(BaseModel):
    """Result model for open-source financial dataset queries."""
    query: str
    total_results: int
    data_points: List[WorldBankIndicator] = []
    error: Optional[str] = None

class CrowdfundingCreator(BaseModel):
    """Nested creator data from Kickstarter API."""
    name: str

class CrowdfundingProject(BaseModel):
    """Represents a single crowdfunding project from the API."""
    platform: str = "Kickstarter" # Set platform default
    project_name: str = Field(..., alias="name")
    url: str
    creator: str # We will flatten the nested object into this field
    goal: float
    pledged: float
    backers: int = Field(..., alias="backers_count")
    status: str = Field(..., alias="state")

class CrowdfundingAnalysisResult(BaseResult):
    """Result of a crowdfunding platform analysis."""
    keyword: str
    projects: List[CrowdfundingProject] = []

class ArbitrationFinding(BaseModel):
    """Details of a specific arbitration or legal dispute finding."""
    case_title: str = Field(..., description="Title or name of the case/dispute.")
    source_url: str = Field(..., description="URL of the source document or article.")
    snippet: str = Field(description="A snippet from the source describing the dispute.")
    case_type: str = Field(default="Unknown", description="Type of dispute (e.g., 'Arbitration', 'Litigation', 'Dispute').")

class ArbitrationSearchResult(BaseResult):
    """Result model for arbitration and legal dispute searches."""
    query: str
    findings: List[ArbitrationFinding] = Field(default_factory=list, description="List of found arbitration cases or disputes.")

class ExportControlFinding(BaseModel):
    """Details of a potential export control, embargo, or trade restriction."""
    entity_name: str = Field(..., description="The name of the entity mentioned.")
    source_list: str = Field(..., description="The name of the sanctions/control list (e.g., 'Consolidated Screening List', 'OFAC').")
    source_url: str = Field(..., description="URL of the source document or listing.")
    details: str = Field(description="Details about the restriction or finding.")

class ExportControlResult(BaseResult):
    """Result model for export control screening."""
    query: str
    findings: List[ExportControlFinding] = Field(default_factory=list, description="List of export control findings.")
    
class LobbyingActivity(BaseModel):
    """Details of a specific lobbying filing or political donation."""
    payee: str = Field(..., description="The lobbying firm or political entity receiving funds.")
    amount: float = Field(..., description="The amount of money involved.")
    date: str = Field(..., description="The date of the filing or donation.")
    source_url: str = Field(..., description="URL of the source data (e.g., OpenSecrets, FEC).")
    purpose: str = Field(description="The stated purpose of the lobbying or donation.")

class LobbyingSearchResult(BaseResult):
    """Result model for lobbying and political influence searches."""
    query: str
    activities: List[LobbyingActivity] = Field(default_factory=list, description="List of lobbying activities and donations found.")

class PatentRDResult(BaseModel):
    """Model for the result of a patent and R&D tracking analysis."""
    topic: str
    company: Optional[str] = None
    analysis_text: str
    error: Optional[str] = None


class MarketIntelResult(BaseModel):
    """Model for the result of a market intelligence analysis."""
    product: str
    industry: str
    country: Optional[str] = None
    analysis_text: str
    error: Optional[str] = None


class ESGMonitorResult(BaseModel):
    """Model for the result of an ESG & sustainability monitoring analysis."""
    company: str
    industry: Optional[str] = None
    analysis_text: str
    error: Optional[str] = None

class FinancialTransaction(BaseModel):
    """Represents a single financial transaction for AML analysis."""
    transaction_id: str
    from_account: str
    to_account: str
    amount: float
    timestamp: datetime
    currency: str = "USD"
    description: Optional[str] = None

class MoneyFlowGraph(BaseModel):
    """Result of a money flow graph visualization."""
    graph_file: str
    total_nodes: int
    total_edges: int
    suspicious_nodes: List[str] = []

class AMLAlert(BaseModel):
    type: str = Field(..., description="Type of alert (e.g., LAYERING, STRAW_COMPANY, STRUCTURING)")
    entity_id: str = Field(..., description="The primary entity ID that triggered the alert")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for the alert")
    message: str = Field(..., description="Human-readable summary of the alert")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting data for the alert")

class AmlPattern(BaseModel):
    """Describes a potential money laundering pattern detected by AI."""
    pattern_type: str = Field(..., description="e.g., 'Structuring', 'Smurfing', 'Layering'")
    description: str = Field(..., description="AI-generated explanation of the pattern")
    involved_accounts: List[str]
    confidence_score: float = Field(..., description="Confidence of the AI's detection (0.0 to 1.0)")
    evidence: List[str] = Field(..., description="List of transaction IDs supporting the finding")

class AmlAnalysisResult(BaseModel):
    """Result from the AI-powered pattern recognition."""
    target: str
    patterns_detected: List[AmlPattern] = []
    summary: str
    error: Optional[str] = None

class ScenarioImpact(BaseModel):
    """Describes the impact of a simulation on a single node."""
    node_affected: str
    impact_type: str = Field(..., description="e.g., 'Sanction', 'Seizure'")
    affected_downstream_nodes: List[str]
    total_value_frozen: float

class ReviewCase(SQLModel, table=True):
    """
    Database model for a single analyst review case.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    alert_type: str = Field(index=True)
    entity_id: str = Field(index=True, description="The *original* entity ID that triggered the alert")
    status: str = Field(default="OPEN", index=True, description="OPEN, IN_REVIEW, ESCALATED, FALSE_POSITIVE")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assignee: Optional[str] = Field(default=None, index=True)
    notes: Optional[str] = None
    
    # For alert fusion
    fusion_count: int = Field(default=1, description="Number of identical alerts fused into this one case")
    
    # Store the PII-masked alert data as a JSON string
    alert_json: str = Field(description="The full AMLAlert object, as JSON, with PII masked.")
class AmlSimulationResult(BaseModel):
    """Result of a 'what-if' scenario simulation."""
    scenario_description: str
    impacts: List[ScenarioImpact]
    error: Optional[str] = None
class DetectedObject(BaseModel):
    """Represents a single object detected in imagery."""
    label: str = Field(..., description="The classification label of the detected object (e.g., 'Vehicle', 'Storage Tank').")
    confidence: float = Field(..., description="The model's confidence in the detection, from 0.0 to 1.0.")
    lat: float = Field(..., description="Latitude of the object's centroid.")
    lon: float = Field(..., description="Longitude of the object's centroid.")
    bounding_box: Optional[List[float]] = Field(None, description="Coordinates of the bounding box [lat_min, lon_min, lat_max, lon_max].")
    timestamp: Optional[datetime] = Field(None, description="Timestamp of the imagery in which the object was detected.")

class ImageryAnalysisResult(BaseModel):
    """Contains the results of a GEOINT++ imagery analysis task."""
    request_id: uuid.UUID = Field(..., description="The unique ID matching the analysis request.")
    status: str = Field(..., description="The processing status (e.g., 'PENDING', 'COMPLETED', 'ERROR').")
    change_detected: Optional[bool] = Field(None, description="Flag indicating if significant change was detected.")
    change_summary: Optional[str] = Field(None, description="A textual summary of the detected changes.")
    change_confidence: Optional[float] = Field(None, description="Confidence in the detected change.")
    objects_detected: List[DetectedObject] = Field(default=[], description="A list of objects found in the 'after' imagery.")
    total_objects: int = Field(default=0, description="Total number of objects detected.")
    imagery_provider: Optional[str] = Field(None, description="The source of the satellite/aerial imagery (e.g., 'Planet', 'Maxar').")
    timestamp_before: Optional[datetime] = Field(None, description="Timestamp of the 'before' image used for comparison.")
    timestamp_after: Optional[datetime] = Field(None, description="Timestamp of the 'after' image used for comparison.")
    correlated_vessel_logs: List[str] = Field(default=[], description="List of vessel IDs/logs (AIS) correlated with activity.")
    correlated_flight_logs: List[str] = Field(default=[], description="List of flight IDs/logs (ADS-B) correlated with activity.")
    error: Optional[str] = Field(None, description="Error message if the analysis failed.")

class AiCoreResult(BaseModel):
    """
    Standard return schema for AI core generation functions.
    """
    analysis_text: str
    error: Optional[str] = None

class FaceAnalysisResult(BaseModel):
    """Result schema for face analysis."""
    file_path: str
    faces_found: int = 0
    face_locations: List[dict] = Field(default_factory=list)
    error: Optional[str] = None

class VoiceComparisonResult(BaseModel):
    """Result schema for voice comparison."""
    file_a: str
    file_b: str
    similarity_score: float = 0.0
    decision: str = "No Match"
    threshold: float = 0.8
    error: Optional[str] = None

class ProfileChangeResult(BaseModel):
    """Result schema for profile change monitoring."""
    profile_url: str
    status: str = "No changes detected."
    changes_found: bool = False
    diff_lines: List[str] = Field(default_factory=list)
    error: Optional[str] = None

# --- Schemas for Leak Scanner ---

class HibpBreach(BaseModel):
    """Details of a single breach from HaveIBeenPwned."""
    name: str = Field(..., description="The name of the breach.")
    domain: str = Field(..., description="The domain of the breached site.")
    breach_date: str = Field(..., description="The date the breach occurred.")
    description: str = Field(..., description="A description of the breach.")
    data_classes: List[str] = Field(..., description="A list of data classes that were compromised.")

class SecretFinding(BaseModel):
    """Represents a potential secret found in a code repository."""
    file_path: str = Field(..., description="The path to the file containing the secret.")
    line_number: int = Field(..., description="The line number where the secret was found.")
    rule_name: str = Field(..., description="The name of the rule that matched.")
    snippet: str = Field(..., description="A snippet of the line containing the secret.")

class LeakScanResult(BaseModel):
    """Consolidated results for leak and credential scanning."""
    target_email: Optional[str] = None
    target_repo: Optional[str] = None
    hibp_breaches: List[HibpBreach] = Field(default_factory=list)
    repo_secrets: List[SecretFinding] = Field(default_factory=list)
    error: Optional[str] = None

# --- Schemas for Threat Pivoting ---

class AsnInfo(BaseModel):
    """ASN and network block information for an IP."""
    asn: Optional[str] = None
    asn_registry: Optional[str] = None
    asn_date: Optional[str] = None
    asn_cidr: Optional[str] = None
    description: Optional[str] = None
    country: Optional[str] = None
    nets: List[Dict[str, Any]] = Field(default_factory=list, description="List of network blocks associated with the ASN.")

class CertInfo(BaseModel):
    """Information from a Certificate Transparency log entry."""
    issuer_name: str
    common_name: str
    name_value: str
    entry_timestamp: str
    not_before: str
    not_after: str

class PivotResult(BaseModel):
    """Consolidated results from pivoting on an IOC."""
    indicator: str = Field(..., description="The IOC (IP or domain) that was pivoted on.")
    indicator_type: str = Field(..., description="The detected type of the indicator (e.g., ipv4, domain).")
    asn_info: Optional[AsnInfo] = None
    reverse_dns: Optional[str] = None
    related_domains_cert: List[CertInfo] = Field(default_factory=list, description="Domains found via Certificate Transparency.")
    error: Optional[str] = None

class DomainMonitoringResult(BaseModel):
    """Result model for domain and account impersonation monitoring."""
    base_domain: str
    lookalikes_found: List[str] = Field(default_factory=list)
    impersonator_accounts: List[Dict[str, str]] = Field(default_factory=list)
    copyright_misuse: List[str] = Field(default_factory=list)
    error: Optional[str] = None

class HoneyAssetResult(BaseModel):
    """Result model for a deployed honey asset."""
    asset_id: str
    status: str # e.g., "deployed", "error"
    fingerprint: str
    tracking_url: str
    error: Optional[str] = None

class LegalTemplateResult(BaseModel):
    """Result model for retrieving a legal escalation template."""
    complaint_type: str
    template_body: str
    contacts: List[str] = Field(default_factory=list)
    error: Optional[str] = None

class ImageAcquisitionTriage(BaseModel):
    """Step A: Acquisition & Triage"""

    file_name: str
    file_path: str
    sha256: str
    phash: str
    clip_embedding_shape: Optional[str] = None
    reverse_search_hits: List[str] = Field(
        default_factory=list, description="Top URLs from reverse image search."
    )
    provenance: Optional[ProvenanceResult] = None


class AutomatedTriageResult(BaseModel):
    """Step B: Automated Triage"""

    exif_analysis: Optional[ImageAnalysisResult] = None
    ela_triage: Optional[ForensicArtifactResult] = None
    ocr_text: Optional[str] = None
    detected_logos: Optional[str] = None
    detected_face_count: int = 0


class SimilarityAttributionResult(BaseModel):
    """Step C: Similarity & Attribution"""

    is_reused_asset: bool = False
    similar_assets_found: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None


class AudioAnomalyResult(BaseModel):
    """Step D: Audio Anomaly Detection Result"""

    analysis_skipped: bool = False
    error: Optional[str] = None
    spectral_flux_anomalies_detected: int = 0
    anomaly_timestamps: List[float] = Field(default_factory=list)


class ManipulationDetectionResult(BaseModel):
    """Step D: Deepfake / Manipulation Detection"""

    deepfake_scan: Optional[DeepfakeAnalysisResult] = None
    audio_anomalies: Optional[AudioAnomalyResult] = None
    sensor_noise_prnu: str = "Out of Scope (Requires specialized sensor library)"


class ImageForensicsReport(BaseModel):
    """Step E: Final Forensics Report"""

    acquisition_triage: ImageAcquisitionTriage
    automated_triage: AutomatedTriageResult
    similarity_attribution: SimilarityAttributionResult
    manipulation_detection: ManipulationDetectionResult
    forensic_summary: str = "Analysis complete. Review results."
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Recommended next steps for an analyst."
    )

class IngestionResult(BaseModel):
    """Result of a single data ingestion task."""
    url: str
    status: str
    content_hash: str
    s3_key: str
    postgres_id: int
    elastic_id: str
    title: Optional[str] = None
    error: Optional[str] = None

class SyntheticMediaAuditResult(BaseModel):
    """
    Result model for a synthetic-media-audit.
    Categorizes and scores the AI-generation origin.
    """
    file_path: str
    media_type: str
    is_synthetic: bool = False
    confidence: float = Field(..., ge=0.0, le=1.0)
    suspected_origin_model: str = "Unknown"
    analysis_details: Dict[str, Any] = Field(default_factory=dict, description="Aggregated findings from other media modules.")
    error: Optional[str] = None

class MentalModelVector(BaseModel):
    """
    A single vector (e.g., bias, value) in a cognitive model.
    """
    vector_type: str = Field(..., description="e.g., 'Core Value', 'Decision-Making Bias', 'Mental Model'")
    description: str = Field(..., description="The specific value or bias (e.g., 'Prioritizes rapid innovation', 'Optimism Bias')")
    evidence_snippet: Optional[str] = Field(None, description="A key quote or snippet from source material supporting this vector.")

class CognitiveMapResult(BaseModel):
    """
    The final, structured result of a cognitive mapping analysis.
    """
    person_name: str
    cognitive_model_summary: Optional[str] = Field(None, description="AI-generated summary of the cognitive model.")
    key_vectors: List[MentalModelVector] = Field(default_factory=list)
    predictive_assessment: Optional[str] = Field(None, description="AI-generated prediction of behavior.")
    error: Optional[str] = None

class FeedConfig(BaseModel):
    """Configuration for a single data feed."""
    name: str = Field(..., description="Unique name for the feed source.")
    type: str = Field(..., description="Type of feed (e.g., 'rss', 'twitter').")
    url: str = Field(..., description="The URL or API endpoint for the feed.")
    interval_seconds: int = Field(600, description="How often to poll the feed.")
    event_type: str = Field("generic_signal", description="The chimera event type to assign.")

class ImageHashResult(BaseModel):
    """Result model for image perceptual and difference hashes."""
    file_path: str
    phash: str = Field(..., help="Perceptual hash of the image.")
    dhash: str = Field(..., help="Difference hash of the image.")


class ReverseImageMatch(BaseModel):
    """A single match from a reverse image search."""
    url: str
    title: str


class ReverseImageSearchResult(BaseModel):
    """Result model for reverse image search."""
    file_path: str
    best_guess: Optional[str] = Field(None, help="Best guess label for the image.")
    matches: List[ReverseImageMatch] = Field([], help="List of matching pages.")


class VaultReceipt(BaseModel):
    """
    A signed and timestamped receipt for a piece of evidence,
    proving its existence and integrity at a specific time.
    """
    file_path: str
    file_hash: str = Field(..., help="SHA-256 hash of the original file.")
    hash_algorithm: str = Field("sha256", help="Algorithm used for file hash.")
    metadata_hash: str = Field(..., help="SHA-256 hash of the signed metadata.")
    signature: str = Field(..., help="Base64 encoded digital signature of the metadata_hash.")
    timestamp_token: Optional[str] = Field(
        None, help="Base64 encoded RFC3161 timestamp token (if requested)."
    )
    timestamp: Optional[datetime] = Field(
        None, help="The datetime extracted from the timestamp token."
    )
class FusedLocationPoint(BaseModel):
    source: str
    latitude: float
    longitude: float
    timestamp: str
    velocity: Optional[float] = None
    altitude: Optional[float] = None
    description: str


class MovingTargetResult(BaseModel):
    target_identifier: str
    current_location: Optional[FusedLocationPoint] = None
    historical_track: List[FusedLocationPoint] = []
    error: Optional[str] = None

class PasteLeak(BaseModel):
    id: str
    source: str # e.g., "Pastebin", "GitHub Gist"
    url: str
    content_snippet: str
    matched_keyword: str
    leak_type: str # e.g., "API_KEY", "PASSWORD", "CONFIG"

class PasteMonitorResult(BaseModel):
    keywords_monitored: List[str]
    leaks_found: List[PasteLeak] = Field(default_factory=list)
    total_leaks: int = 0

class TrustedMediaAIMetadata(BaseModel):
    """Schema for AI model usage details."""
    model_name: str
    seed: Optional[str] = None
    prompt: Optional[str] = None

class TrustedMediaManifest(BaseModel):
    """
    The sidecar JSON manifest for a master image, as per best practices.
    """
    master_sha256: str = Field(..., description="SHA256 hash of the master file.")
    source_files: List[str] = Field(default_factory=list)
    editor_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ai_models_used: List[TrustedMediaAIMetadata] = Field(default_factory=list)
    consent_ids: List[str] = Field(default_factory=list)
    project_id: str
    license: Optional[str] = "All Rights Reserved"
    author: Optional[str] = "Chimera-Intel Corp"

class MediaProductionPackage(BaseModel):
    """Final output package details."""
    master_file_path: str
    manifest: TrustedMediaManifest
    derivatives: List[str] = Field(default_factory=list)
    manifest_vault_receipt_id: str
    arg_nodes_created: List[str]
    arg_rels_created: int

class VehicleInfoResult(BaseModel):
    """Pydantic model for holding decoded VIN information."""
    
    VIN: Optional[str] = Field(None, description="The VIN queried.")
    Make: Optional[str] = Field(None, description="Vehicle Manufacturer.")
    Model: Optional[str] = Field(None, description="Vehicle Model.")
    ModelYear: Optional[str] = Field(None, description="Vehicle Model Year.")
    VehicleType: Optional[str] = Field(None, description="Vehicle Type.")
    BodyClass: Optional[str] = Field(None, description="Vehicle Body Class.")
    EngineCylinders: Optional[str] = Field(None, description="Number of engine cylinders.")
    DisplacementL: Optional[str] = Field(None, description="Engine displacement in liters.")
    FuelTypePrimary: Optional[str] = Field(None, description="Primary fuel type.")
    PlantCountry: Optional[str] = Field(None, description="Manufacturing plant country.")
    PlantCity: Optional[str] = Field(None, description="Manufacturing plant city.")
    Manufacturer: Optional[str] = Field(None, description="Full manufacturer name.")
    ErrorCode: Optional[str] = Field(None, description="Error code from API.")
    ErrorText: Optional[str] = Field(None, description="Error description from API.")

    class Config:
        # Allow extra fields from the API response without failing validation
        extra = "ignore"


class VehicleScanResult(BaseModel):
    """Pydantic model for the complete VIN scan result."""
    
    query_vin: str
    info: Optional[VehicleInfoResult] = None
    error: Optional[str] = None
class SyntheticMediaAuditResult(BaseModel):
    """
    Result model for a synthetic-media-audit.
    Categorizes and scores the AI-generation origin.
    """
    file_path: str
    media_type: str
    is_synthetic: bool = False
    confidence: float = Field(..., ge=0.0, le=1.0)
    suspected_origin_model: str = "Unknown"
    analysis_details: Dict[str, Any] = Field(default_factory=dict, description="Aggregated findings from other media modules.")
    error: Optional[str] = None
class ImageSourceType(str, Enum):
    """Enumeration for the source of an ingested image."""
    GOOGLE_IMAGES = "google_images"
    TWITTER = "twitter"
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    YOUTUBE_FRAME = "youtube_frame"
    REDDIT = "reddit"
    TIKTOK = "tiktok"
    PINTEREST = "pinterest"
    META_AD_LIBRARY = "meta_ad_library"
    GOOGLE_ADS = "google_ads"
    ECOMMERCE = "ecommerce" # Amazon, eBay, etc.
    NEWS = "news"
    PRESS_RELEASE = "press_release"
    DARK_WEB = "dark_web"
    INTERNAL = "internal"
    PARTNER = "partner"
    REVERSE_SEARCH = "reverse_search" # TinEye, Google Vision, etc.
    OTHER = "other"


class ImageFeatures(BaseModel):
    """Indexed features for an ingested image."""
    perceptual_hash: Optional[str] = Field(None, description="Perceptual hash (e.g., pHash) of the image.")
    difference_hash: Optional[str] = Field(None, description="Difference hash (dHash) of the image.")
    embedding_vector_shape: Optional[str] = Field(None, description="Shape of the stored embedding vector (e.g., '1x512').")
    embedding_model_name: Optional[str] = Field(None, description="Name of the model used for embedding (e.g., 'openai/clip-vit-base-patch32').")
    embedding_vector_shape: Optional[str] = Field(None, description="Shape of the stored embedding vector (e.g., '1x512').")

class ImageEnrichment(BaseModel):
    """Enrichment data extracted from an image."""
    ocr_text: Optional[str] = Field(None, description="Text extracted via OCR.")
    detected_logos: List[str] = Field(default_factory=list, description="Logos detected in the image.")
    detected_faces_count: int = Field(0, description="Number of faces detected.")
    face_locations: Optional[List[Dict[str, Any]]] = Field(None, description="Bounding boxes for detected faces.")
    # Re-using existing EXIF model
    exif_data: Optional[ExifData] = Field(None, description="Extracted EXIF metadata.")


class IngestedImageRecord(BaseModel):
    """
    A normalized record for a single image ingested into the system.
    This model represents the metadata stored in the database (e.g., Postgres).
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for this ingestion record.")
    source_url: HttpUrl = Field(..., description="The original URL where the image was found.")
    source_type: ImageSourceType = Field(..., description="The category of the source (e.g., 'twitter', 'news').")
    source_context_url: Optional[HttpUrl] = Field(None, description="The page URL where the image was embedded (e.g., the tweet URL).")
    
    ingested_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of when the image was ingested.")
    original_timestamp: Optional[datetime] = Field(None, description="The original creation/post-time of the image, if available.")

    # Normalization
    resolution: Optional[str] = Field(None, description="Image resolution, e.g., '1920x1080'.")
    mime_type: Optional[str] = Field(None, description="MIME type of the image, e.g., 'image/jpeg'.")
    file_size_bytes: Optional[int] = Field(None, description="Size of the image file in bytes.")

    # Storage & Hashing
    storage_key: str = Field(..., description="The key (path) where the raw image is stored (e.g., S3 key).")
    sha256_hash: str = Field(..., description="SHA-256 hash of the raw image file for deduplication and integrity.")

    # Indexed Features & Enrichment
    features: Optional[ImageFeatures] = None
    enrichment: Optional[ImageEnrichment] = None

    # Graph Linking
    arg_node_id: Optional[str] = Field(None, description="The ID of the corresponding node in the ARG (graph database).")
    linked_entities: List[str] = Field(default_factory=list, description="List of entity IDs linked to this image in the ARG.")
    
    error: Optional[str] = Field(None, description="Any error that occurred during ingestion.")

    class Config:
        orm_mode = True
class AiGenerationTraceResult(BaseModel):
    is_ai_generated: bool
    confidence_score: float
    suspected_model: str
    evidence: List[str]
    error: Optional[str] = None


# New schemas for Forensic Artifact Scan results
# Used by: ForensicArtifacts
class ElaResult(BaseModel):
    status: str
    mean_ela_value: Optional[float] = None
    max_ela_value: Optional[float] = None
    is_suspicious: Optional[bool] = False
    message: Optional[str] = None


class PrnuMatch(BaseModel):
    status: str
    noise_residual_variance: Optional[float] = None
    message: Optional[str] = None


class CloneDetection(BaseModel):
    status: str
    cloned_keypoints_found: Optional[int] = None
    is_suspicious: Optional[bool] = False
    message: Optional[str] = None


# THIS IS THE FIX: Define ForensicArtifacts before it is used
# Used by: BrandMisuseAuditResult
class ForensicArtifacts(BaseModel):
    ela_result: ElaResult
    prnu_match: PrnuMatch
    clone_detection: CloneDetection


# ---
# NEW COMPINT SCHEMAS (Define these after dependencies)
# ---

class CompetitiveImintResult(BaseModel):
    file_path: str
    use_case: str
    analysis: str = Field(..., description="The AI-generated analysis for the use case.")


class CreativeAttributionResult(BaseModel):
    file_path: str
    phash: str
    clip_embedding_shape: str
    reverse_search_hits: List[str] = Field(
        description="Public URLs found matching the image pHash."
    )
    # Assumes SimilarityAttributionResult is defined *earlier* in schemas.py
    internal_similarity: "SimilarityAttributionResult" = Field(
        description="Similarity results from the internal vector database."
    )


class BrandMisuseAuditResult(BaseModel):
    file_path: str
    counterfeit_analysis: str = Field(
        description="AI analysis on potential brand misuse or counterfeit."
    )
    # This now works, because ForensicArtifacts is defined above
    forensic_artifacts: Optional["ForensicArtifacts"] = Field(
        description="Forensic scan for manipulation artifacts (e.g., added logos)."
    )


class CounterDisinfoResult(BaseModel):
    file_path: str
    # Assumes DeepfakeAnalysisResult is defined *earlier* in schemas.py
    deepfake_scan: Optional["DeepfakeAnalysisResult"] = None
    # This now works as AiGenerationTraceResult is defined above
    ai_trace: Optional["AiGenerationTraceResult"] = None


class EvidenceReceiptResult(BaseModel):
    file_path: str
    target_project: str
    receipt_id: str = Field(description="The unique ID for the stored evidence.")
    message: str = "Successfully encrypted and stored with chain-of-custody."

class EntityRiskResult(BaseResult):
    company_name: str
    jurisdiction: str
    risk_score: int = Field(default=0, description="Composite risk score (0-100)")
    risk_factors: List[str] = Field(default_factory=list, description="Explainable reasons for the score")
    pep_links: int = Field(default=0, description="Number of linked Politically Exposed Persons")
    adverse_media_hits: int = Field(default=0, description="Number of negative news articles")
    shell_company_indicators: List[str] = Field(default_factory=list)
    sanctions_hits: int = Field(default=0, description="Number of direct hits on sanctions lists")
class EntityResolutionResult(BaseModel):
    """
    A placeholder for the result of a global entity resolution.
    This would contain all linked entities (wallets, companies, people)
    and their risk profiles.
    """
    entity_id: str
    status: str
    risk_profile: Optional[EntityRiskResult] = None
    linked_entities: List[Dict[str, Any]] = Field(default_factory=list)


# --- NEW: Trade-to-Payment Correlation Models (Database-backed) ---

class TradeRecord(SQLModel, table=True):
    """
    Database model for a trade record (e.g., from a Bill of Lading).
    """
    id: Optional[int] = SQLField(default=None, primary_key=True)
    record_id: str = SQLField(index=True, unique=True, description="Bill of Lading or unique trade ID")
    exporter_name: str = SQLField(index=True)
    importer_name: str = SQLField(index=True)
    amount: float
    currency: str
    ship_date: date
    description_of_goods: str

class PaymentRecord(SQLModel, table=True):
    """
    Database model for a financial payment record (e.g., SWIFT, TT).
    """
    id: Optional[int] = SQLField(default=None, primary_key=True)
    record_id: str = SQLField(index=True, unique=True, description="SWIFT, wire, or unique transaction ID")
    sender_name: str = SQLField(index=True)
    receiver_name: str = SQLField(index=True)
    amount: float
    currency: str
    payment_date: date
    origin_bank_country: str = SQLField(max_length=3)

class TradeCorrelationResult(BaseModel):
    """
    Pydantic model for the result of a trade/payment correlation check.
    """
    trade_id: str
    payment_id: str
    is_match: bool = False
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    mismatch_reasons: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)

# --- PHYSINT Enterprise Schemas ---

class VesselPosition(BaseResult):
    """Holds live positional data for a maritime vessel from a free AIS API."""
    imo: int
    name: str
    latitude: float
    longitude: float
    course: float = Field(..., alias="cog")
    speed: float = Field(..., alias="sog")
    timestamp: str = Field(..., alias="last_update")

class TradeManifest(BaseModel):
    """
    Represents a single shipping manifest (Bill of Lading).
    NOTE: This schema is for a proprietary, paid trade data API.
    """
    bill_of_lading_id: str
    shipper_name: str
    consignee_name: str
    vessel_imo: Optional[str] = None
    port_of_lading: str
    port_of_discharge: str
    cargo_description: str
    ship_date: str

class TradeManifestResult(BaseResult):
    """The result of a trade manifest search for a company."""
    company_name: str
    manifests: List[TradeManifest] = Field(default_factory=list)
    total_manifests: int = 0

class SupplyChainAnomaly(BaseModel):
    """Represents a single detected supply chain anomaly."""
    anomaly_type: str  # e.g., "High-Risk Port", "Suspicious Routing"
    description: str
    severity: str  # "Low", "Medium", "High"
    related_bill_of_lading: Optional[str] = None
    related_vessel_imo: Optional[str] = None

class SupplyChainAnalysisResult(BaseResult):
    """The final report from a supply chain anomaly analysis."""
    target_company: str
    analysis_summary: str
    anomalies_found: List[SupplyChainAnomaly] = Field(default_factory=list)
    total_anomalies: int = 0

class TriageTask(BaseModel):
    """Model for a single analyst triage task."""
    task_id: str = Field(default_factory=lambda: f"triage-{uuid.uuid4()}")
    media_url: str
    source: str
    provenance_data: Dict[str, Any] = Field(default_factory=dict)
    detection_result: ManipulationDetectionResult
    status: str = "pending"  # pending, confirmed_positive, false_positive
    analyst_notes: Optional[str] = None

class BrandThreat(BaseModel):
    """Model for a scored and prioritized threat."""
    threat_id: str = Field(default_factory=lambda: f"threat-{uuid.uuid4()}")
    media_url: str
    source: str
    triage_status: str
    detection_score: float = Field(..., ge=0, le=1)
    reach_score: float = Field(..., ge=0, le=1)
    final_threat_score: float = Field(..., ge=0, le=1)

class SourceTriageResult(BaseModel):
    """Result model for a source triage check."""
    url: str
    domain: str
    is_social_media: bool = False
    domain_creation_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    page_title: Optional[str] = None
    profile_details: Dict[str, str] = Field(default_factory=dict)
    indicators: List[str] = Field(default_factory=list)

class TemporalAnalysisResult(BaseResult):
    """Result from temporal artifact analysis (e.g., optical flow, 3D-CNN)."""
    artifacts_found: List[str] = []
    temporal_inconsistency_score: float = 0.0
    details: str = ""

class SyntheticVoiceAnalysisResult(BaseResult):
    """Result from a dedicated synthetic voice detector (ASV)."""
    is_synthetic: bool = False
    confidence: float = 0.0
    details: str = ""

class EnsembleAnalysisResult(BaseResult):
    """Final combined result from all detectors."""
    final_fake_probability: float = 0.0
    frame_analysis: Optional[DeepfakeAnalysisResult] = None
    temporal_analysis: Optional[TemporalAnalysisResult] = None
    voice_analysis: Optional[SyntheticVoiceAnalysisResult] = None
    explainability_report: Dict[str, Any] = {}

class MediaAssetStatus(str, Enum):
    """Enumeration for the approval status of a media asset."""
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"

class ConsentRecord(BaseModel):
    """
    Model for a consent form log.
    This record is stored in the vault, and its receipt_id is
    used in the TrustedMediaManifest.
    """
    consent_id: str = Field(
        default_factory=lambda: f"consent-{uuid.uuid4()}",
        description="Unique ID for this consent record."
    )
    person_name: str
    contact_info: Optional[str] = None
    details: str = Field(
        description="Details of what the consent covers (e.g., 'Use of likeness for Project Orion')."
    )
    consent_form_sha256: str = Field(
        description="SHA-256 hash of the signed consent form file."
    )
    consent_form_storage_id: str = Field(
        description="The receipt_id of the encrypted consent form in the Evidence Vault."
    )
    log_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

class ImageHashResult(BaseModel):
    phash: Optional[str] = None
    dhash: Optional[str] = None

class ReverseImageMatch(BaseModel):
    url: str
    title: str

class ReverseImageSearchResult(BaseModel):
    best_guess: Optional[str] = None
    matches: List[ReverseImageMatch] = Field(default_factory=list)

class VaultReceipt(BaseModel):
    file_path: str
    file_hash: str
    hash_algorithm: str = "sha256"
    metadata_hash: str
    signature: str
    timestamp: Optional[datetime] = None
    timestamp_token: Optional[str] = None

class VaultExportResult(BaseModel):
    original_file: str
    original_hash_sha256: str
    exported_file: str
    exported_hash_sha256: str
    export_format: str
    exported_receipt: VaultReceipt

class ServiceBanner(BaseModel):
    name: str = "unknown"
    banner: str
    software: Optional[str] = Field(None, description="Parsed software name, e.g., OpenSSH")
    version: Optional[str] = Field(None, description="Parsed software version, e.g., 8.9p1")

class PortScanResult(BaseModel):
    port: int
    is_open: bool
    service: Optional[ServiceBanner] = None

class NetworkScanReport(BaseModel):
    target_ip: str
    ports_scanned: List[int]
    open_ports: List[PortScanResult]
