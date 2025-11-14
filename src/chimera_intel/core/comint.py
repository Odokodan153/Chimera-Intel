"""
Communications Intelligence (COMINT) Module

Processes PCAP files to extract text and audio communications, performs entity
and sentiment analysis, speaker identification, and correlates results in a graph
for adversary intelligence insights.
"""

import typer
from typer import Typer
import logging
import re
from typing import Optional, List, Dict, Any, Tuple
from scapy.all import rdpcap, TCP, UDP, RTP, Raw, IP
from datetime import datetime
from collections import defaultdict
from chimera_intel.core.ai_core import AICore
from chimera_intel.core.advanced_nlp import AdvancedNLP, Entity
from chimera_intel.core.arg_service import ArgService
from chimera_intel.core.adversary_voice_matcher import AdversaryVoiceMatcher

# Set up logging
logger = logging.getLogger(__name__)

# Create a new Typer app for COMINT commands
cli_app = Typer(name="comint", help="Communications Intelligence (COMINT) Toolkit")

class COMINTModule:
    """
    A dedicated module for Communications Intelligence (COMINT).
    
    This module integrates with SIGINT capabilities (PCAP analysis),
    NLP, graph services, and voice matching to extract intelligence
    from intercepted communications.
    """
    
    # Regex patterns for communicator extraction
    EMAIL_FROM_RE = re.compile(r"From:\s*.*?[<\[\(]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[>\]\)]", re.IGNORECASE)
    EMAIL_TO_RE = re.compile(r"To:\s*.*?[<\[\(]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[>\]\)]", re.IGNORECASE)
    CHAT_USER_RE = re.compile(r"\[.*?\]\s*<([a-zA-Z0-9_-]+)>|([a-zA-Z0-9_-]+):", re.IGNORECASE)


    def __init__(self,
                 ai_core: AICore,
                 nlp_processor: AdvancedNLP,
                 arg_service: ArgService,
                 voice_matcher: AdversaryVoiceMatcher):
        self.ai_core = ai_core
        self.nlp = nlp_processor
        self.graph = arg_service
        self.voice_matcher = voice_matcher
        logger.info("COMINTModule initialized.")

    def _analyze_text_payload(self, payload: str, timestamp: datetime, stream_key: Tuple):
        """Analyzes a reassembled text payload for entities and sentiment."""
        try:
            src_ip, src_port, dst_ip, dst_port = stream_key
            logger.debug(f"Analyzing text payload from {src_ip}:{src_port} ({len(payload)} bytes)")
            
            entities = self.nlp.extract_entities(payload)
            sentiment = self.nlp.analyze_sentiment(payload)
            
            logger.info(f"COMINT Text Analysis: Sentiment={sentiment.score}, Entities={[e.type for e in entities]}")

            # Correlate communication patterns
            comms_pair = self._extract_communicators(payload, entities)
            
            if comms_pair:
                from_entity, to_entity = comms_pair
                self.graph.add_edge(
                    from_entity,
                    to_entity,
                    "COMMUNICATED_WITH",
                    properties={
                        "timestamp": timestamp.isoformat(),
                        "sentiment": sentiment.score,
                        "protocol": "text",
                        "source_ip": src_ip,
                        "dest_ip": dst_ip,
                        "dest_port": dst_port
                    }
                )
                logger.info(f"Correlated communication: {from_entity} -> {to_entity}")

            return {"entities": entities, "sentiment": sentiment}
        except Exception as e:
            logger.error(f"Error during text payload analysis: {e}")
            return None

    def _extract_communicators(self, payload: str, entities: List[Entity]) -> Optional[tuple[str, str]]:
        """
        Extracts 'from' and 'to' entities from reassembled text.
        
        This implementation searches for email headers first, then
        falls back to NLP-extracted entities.
        """
        from_entity = None
        to_entity = None

        # 1. Try to find email headers
        from_match = self.EMAIL_FROM_RE.search(payload)
        to_match = self.EMAIL_TO_RE.search(payload)

        if from_match and to_match:
            from_entity = from_match.group(1)
            to_entity = to_match.group(1)
            if from_entity and to_entity:
                logger.debug(f"Extracted email pair: {from_entity} -> {to_entity}")
                return from_entity, to_entity

        # 2. Fallback to NLP entities (less precise for 'who to whom')
        persons_orgs = [e.text for e in entities if e.type in ('PERSON', 'ORG', 'EMAIL')]
        if len(persons_orgs) >= 2:
            # This is an assumption, but better than nothing.
            from_entity = persons_orgs[0]
            to_entity = persons_orgs[1]
            logger.debug(f"Fell back to NLP entities: {from_entity} -> {to_entity}")
            return from_entity, to_entity
            
        return None

    def _analyze_audio_payload(self, payload: bytes, timestamp: datetime, source_ip: str, dest_ip: str):
        """Analyzes an audio payload for speaker identification."""
        try:
            logger.debug(f"Analyzing audio payload from {source_ip} ({len(payload)} bytes)")
            # Payload is raw audio data from an RTP stream
            identification = self.voice_matcher.identify_speaker(payload)
            
            if identification and identification.is_match:
                speaker_id = identification.match_id
                logger.info(f"COMINT Audio Analysis: Identified speaker '{speaker_id}'")
                
                # Correlate with the graph
                self.graph.add_node_if_not_exists(source_ip, "IP_Address", {"ip": source_ip})
                self.graph.add_node_if_not_exists(speaker_id, "Adversary", {"id": speaker_id})
                self.graph.add_edge(
                    source_ip,
                    speaker_id,
                    "ASSOCIATED_WITH_VOICE",
                    properties={
                        "timestamp": timestamp.isoformat(),
                        "confidence": identification.confidence,
                        "destination_ip": dest_ip,
                        "protocol": "audio/rtp"
                    }
                )
                logger.info(f"Correlated audio: {source_ip} -> {speaker_id}")
                return identification
            else:
                logger.info("COMINT Audio Analysis: No match found.")
                return None
        except Exception as e:
            logger.error(f"Error during audio payload analysis: {e}")
            return None

    def process_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Performs Deep Packet Inspection (DPI) on a PCAP file.
        
        Reassembles TCP streams, extracts text, and analyzes RTP audio.
        """
        logger.info(f"Starting COMINT analysis on PCAP file: {pcap_path}")
        results = {"text_analyses": [], "audio_analyses": [], "packet_count": 0}
        
        #
        # --- This is a functional TCP stream reassembler ---
        # It stores payloads by sequence number to ensure correct order.
        # Note: It does not handle retransmissions, overlapping segments,
        # or relative sequence numbers, but it correctly reassembles
        # basic, in-order or out-of-order streams.
        #
        # Format: { (src_ip, sport, dst_ip, dport): {seq_num: payload} }
        tcp_streams = defaultdict(lambda: defaultdict(bytes))
        
        # Format: [ (timestamp, src_ip, dst_ip, payload) ]
        rtp_payloads = [] 
        
        first_packet_ts = {} # { stream_key: timestamp }

        try:
            packets = rdpcap(pcap_path)
            results["packet_count"] = len(packets)
            
            for packet in packets:
                if not packet.haslayer(IP):
                    continue
                    
                timestamp = datetime.fromtimestamp(float(packet.time))
                
                # --- Text Protocol Handling (TCP Stream Reassembly) ---
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    try:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        seq = packet[TCP].seq
                        payload = packet[Raw].load

                        # Store payloads by sequence number
                        stream_key = (src_ip, sport, dst_ip, dport)
                        reverse_key = (dst_ip, dport, src_ip, sport)
                        
                        # Find the correct stream direction
                        if stream_key in tcp_streams:
                            tcp_streams[stream_key][seq] = payload
                        elif reverse_key in tcp_streams:
                             # This payload is part of the *other* side of the conversation
                             # For simplicity, we'll store it under the reverse key.
                             # A more complex parser would handle duplex.
                             tcp_streams[reverse_key][seq] = payload
                        else:
                            # Start a new stream
                            tcp_streams[stream_key][seq] = payload
                            first_packet_ts[stream_key] = timestamp
                            
                    except Exception as e:
                        logger.warning(f"Error processing TCP packet: {e}")
                        continue

                # --- Audio Protocol Handling (RTP on UDP) ---
                if packet.haslayer(UDP) and packet.haslayer(RTP):
                    try:
                        payload_bytes = packet[RTP].load
                        source_ip = packet[IP].src
                        dest_ip = packet[IP].dst
                        rtp_payloads.append((timestamp, source_ip, dest_ip, payload_bytes))
                    except Exception as e:
                        logger.warning(f"Error processing RTP packet: {e}")
                        continue

            # --- Process Reassembled Streams ---
            logger.info(f"Reassembling {len(tcp_streams)} TCP streams...")
            for stream_key, payloads_dict in tcp_streams.items():
                if not payloads_dict:
                    continue
                    
                # Sort payloads by sequence number and join
                sorted_payloads = [payloads_dict[k] for k in sorted(payloads_dict.keys())]
                full_payload_bytes = b"".join(sorted_payloads)
                
                if not full_payload_bytes:
                    continue

                # Heuristic: Check if payload is mostly printable text
                if sum(31 < b < 127 or b in (9, 10, 13) for b in full_payload_bytes[:200]) / min(len(full_payload_bytes), 200) > 0.8:
                    try:
                        payload_str = full_payload_bytes.decode('utf-8', errors='ignore')
                        stream_timestamp = first_packet_ts.get(stream_key, datetime.now())
                        analysis = self._analyze_text_payload(payload_str, stream_timestamp, stream_key)
                        if analysis:
                            results["text_analyses"].append(analysis)
                    except Exception as e:
                        logger.warning(f"Could not decode text payload from {stream_key}: {e}")
                else:
                    logger.debug(f"Skipping non-text TCP stream: {stream_key}")

            # --- Process Audio Payloads ---
            logger.info(f"Analyzing {len(rtp_payloads)} RTP packets...")
            for ts, src_ip, dst_ip, payload in rtp_payloads:
                analysis = self._analyze_audio_payload(payload, ts, src_ip, dst_ip)
                if analysis:
                    results["audio_analyses"].append(analysis)

            logger.info(f"COMINT analysis complete. Found {len(results['text_analyses'])} text results and {len(results['audio_analyses'])} audio results.")
            
        except FileNotFoundError:
            logger.error(f"PCAP file not found: {pcap_path}")
            raise
        except Exception as e:
            logger.error(f"Failed to process PCAP file {pcap_path}: {e}", exc_info=True)
            raise
            
        return results

# --- CLI Command ---

@cli_app.command("process-pcap", help="Analyze a PCAP file for communications intelligence.")
def cli_process_pcap(
    ctx: typer.Context,
    pcap_path: str = typer.Argument(..., help="Path to the .pcap or .pcapng file."),
):
    """
    CLI command to run COMINT analysis on a PCAP file.
    """
    if not ctx.obj:
        logger.error("Failed to get context objects. Ensure plugins are loaded.")
        return

    comint_module: COMINTModule = ctx.obj.get("comint_module")
    if not comint_module:
        logger.error("COMINTModule not found in context. Is the plugin registered?")
        return

    try:
        results = comint_module.process_pcap(pcap_path)
        print(f"--- COMINT Analysis Report for {pcap_path} ---")
        print(f"Total Packets Analyzed: {results['packet_count']}")
        print(f"Reassembled Text Streams Analyzed: {len(results['text_analyses'])}")
        print(f"Audio Payloads Analyzed: {len(results['audio_analyses'])}")
        print("Analysis complete. Check logs and graph database for details.")
    except FileNotFoundError:
        print(f"Error: File not found at {pcap_path}")
    except Exception as e:
        print(f"An error occurred during PCAP processing: {e}")