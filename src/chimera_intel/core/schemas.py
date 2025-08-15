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
    domain_name: str = Field(..., alias='domain-name')
    dns_a: Optional[List[str]] = Field(None, alias='dns-a')
    dns_aaaa: Optional[List[str]] = Field(None, alias='dns-aaaa')
    dns_mx: Optional[List[str]] = Field(None, alias='dns-mx')
    dns_ns: Optional[List[str]] = Field(None, alias='dns-ns')

class TyposquatResult(BaseModel):
    """Model for the result of a dnstwist typosquatting scan."""
    results: Optional[List[TyposquatFuzzer]] = None
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
    dns_records_to_query: List[str] = ['A', 'MX']

class ConfigModules(BaseModel):
    """Configuration for all modules from config.yaml."""
    footprint: ConfigFootprint

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
    data_points: List[float]
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
    added: List[str]
    removed: List[str]

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
    notes: Optional[str] = None # For messages like "Not enough data"

# --- Vulnerability Scanner Models ---

class PortDetail(BaseModel):
    """Model for details about a single open port."""
    port: int
    state: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None

class HostScanResult(BaseModel):
    """Model for the full Nmap scan results for a single host."""
    host: str
    state: str
    open_ports: List[PortDetail]

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