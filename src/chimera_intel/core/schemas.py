# src/chimera_intel/core/schemas.py

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# --- Scan Result Models ---

class ScoredResult(BaseModel):
    """A model for a result that has sources and a confidence score."""
    domain: Optional[str] = None
    technology: Optional[str] = None
    confidence: str
    sources: List[str]

class SubdomainReport(BaseModel):
    """A model for the subdomain report."""
    total_unique: int
    results: List[ScoredResult]

class FootprintData(BaseModel):
    """A model for the data within the footprint module."""
    whois_info: Dict[str, Any]
    dns_records: Dict[str, Any]
    subdomains: SubdomainReport

class FootprintResult(BaseModel):
    """The main result model for a footprint scan."""
    domain: str
    footprint: FootprintData

# --- Configuration Models ---

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
    """The main model for the entire config.yaml file."""
    network: ConfigNetwork
    modules: ConfigModules