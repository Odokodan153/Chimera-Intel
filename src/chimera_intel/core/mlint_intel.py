"""
MLint Intelligence Gathering
(Updated for config, robustness, PEP, and NLP classification)
"""

import asyncio
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from newsapi import NewsApiClient 
from tenacity import retry, stop_after_attempt, wait_exponential
from mlint_schemas import Entity, AdverseMediaHit, EntityType
from mlint_clients import AbstractSanctionsClient, AbstractUboClient, AbstractChainAnalysisClient, AbstractPepClient
from mlint_ai import classify_adverse_media_ai
from mlint_config import settings

# Configure logging
log = logging.getLogger(__name__)

class IntelligenceAggregator:
    def __init__(
        self,
        sanctions_client: AbstractSanctionsClient,
        ubo_client: AbstractUboClient,
        chain_client: AbstractChainAnalysisClient,
        pep_client: AbstractPepClient # <-- Inject PEP client
    ):
        self.sanctions_client = sanctions_client
        self.ubo_client = ubo_client
        self.chain_client = chain_client
        self.pep_client = pep_client # <-- Store PEP client
        
        self.news_api_key = settings.news_api_key
        if self.news_api_key:
            self.news_client = NewsApiClient(api_key=self.news_api_key)
        else:
            self.news_client = None
            log.warning("NEWS_API_KEY not set in config. Adverse media search will be disabled.")

    async def gather_entity_intelligence(self, entity: Entity) -> Dict[str, Any]:
        """
        Orchestrates all intelligence gathering for a single entity.
        (Updated for PEP client and robust error handling)
        """
        
        # --- PHASE 1, Step 2: Fix Enum Handling ---
        # Check against the Enum, not a string
        is_company = (entity.entity_type == EntityType.COMPANY)
        
        tasks = {
            "sanctions": self.sanctions_client.check_entity(entity.name, entity.entity_type.value),
            "pep_screening": self.pep_client.check_entity_pep(entity.name), # <-- New PEP Task
            "adverse_media": self.gather_adverse_media(entity.name),
            "ubo": (
                self.ubo_client.get_ubo(entity.name, entity.jurisdiction)
                if is_company and entity.jurisdiction
                else asyncio.sleep(0, result=None) # No-op
            ),
            "chain_analytics": self._gather_wallet_intel(entity)
        }
        
        # --- PHASE 2, Step 6: Error Isolation (return_exceptions=True) ---
        task_names = list(tasks.keys())
        task_list = list(tasks.values())
        
        # return_exceptions=True prevents one failed task from stopping all
        results = await asyncio.gather(*task_list, return_exceptions=True)
        
        intel = {}
        for name, result in zip(task_names, results):
            if isinstance(result, Exception):
                # Log the full exception for debugging
                log.error(f"Intelligence task '{name}' failed for entity '{entity.name}': {result}", exc_info=result)
                intel[name] = {"error": str(result)} # Store simple error string
            else:
                intel[name] = result # Store successful result
        # --- End of Error Isolation ---
        
        return intel

    async def _gather_wallet_intel(self, entity: Entity) -> List[Dict[str, Any]]:
        # --- PHASE 1, Step 2 (Fix): Check Enum, not string ---
        if entity.entity_type != EntityType.WALLET and not entity.addresses:
            return []
            
        wallet_tasks = [
            self.chain_client.get_wallet_risk(addr) 
            for addr in entity.addresses
        ]
        
        # Also use return_exceptions=True here for robustness
        results = await asyncio.gather(*wallet_tasks, return_exceptions=True)
        
        # Filter out exceptions, returning only successful results
        final_results = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                log.error(f"Wallet risk check failed for address {entity.addresses[i]}: {res}")
                final_results.append({"address": entity.addresses[i], "error": str(res)})
            else:
                final_results.append(res)
        return final_results


    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10)) # <-- New Retry
    async def gather_adverse_media(self, entity_name: str) -> List[AdverseMediaHit]:
        """
        Performs OSINT/Adverse Media search using a REAL News API.
        (Updated with NLP classification)
        """
        if not self.news_client:
            return []

        log.info(f"Gathering adverse media for: {entity_name}")
        query = f'"{entity_name}" AND (fraud OR "money laundering" OR sanction OR bribery OR crime OR corruption OR investigation)'
        from_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

        try:
            loop = asyncio.get_event_loop()
            api_response = await loop.run_in_executor(
                None,
                lambda: self.news_client.get_everything(
                    q=query,
                    language='en',
                    from_param=from_date,
                    sort_by='relevancy',
                    page_size=20
                )
            )

            hits = []
            if api_response.get('status') == 'ok':
                for article in api_response.get('articles', []):
                    
                    # --- New: NLP Classification ---
                    headline = article.get('title')
                    snippet = article.get('description') or ""
                    
                    if not headline or not snippet: # Skip articles without content
                        continue
                        
                    text_to_classify = f"{headline} {snippet}"
                    
                    # Run classification (this calls the new mlint_ai function)
                    categories = await classify_adverse_media_ai(text_to_classify)
                    # --- End New ---
                    
                    hits.append(AdverseMediaHit(
                        url=article.get('url'),
                        headline=headline,
                        source_name=article.get('source', {}).get('name'),
                        publish_date=datetime.fromisoformat(article.get('publishedAt').replace('Z', '+00:00')) if article.get('publishedAt') else None,
                        snippet=snippet,
                        risk_categories=categories # <-- Use classified categories
                    ))
            return hits
        except Exception as e:
            log.error(f"Adverse media search failed for '{entity_name}': {e}")
            if "apiKeyInvalid" in str(e):
                log.error("NewsAPI key is invalid or missing.")
            raise # Re-raise exception to be caught by asyncio.gather or retry