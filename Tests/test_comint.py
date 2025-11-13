import pytest
from unittest.mock import MagicMock, patch, ANY
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, RTP, Raw

# Make sure to import the updated module
from chimera_intel.core.comint import COMINTModule
from chimera_intel.core.advanced_nlp import Sentiment, Entity
from chimera_intel.core.adversary_voice_matcher import VoiceMatchResult

# Mock NLP and Voice models
MockSentiment = Sentiment(label="POSITIVE", score=0.95)

MockVoiceMatch = VoiceMatchResult(is_match=True, match_id="Adversary_X", confidence=0.88)
MockNoVoiceMatch = VoiceMatchResult(is_match=False)

@pytest.fixture
def mock_dependencies():
    """Provides mocked dependencies for the COMINTModule."""
    ai_core = MagicMock()
    nlp_processor = MagicMock()
    arg_service = MagicMock()
    voice_matcher = MagicMock()
    
    # Configure mock return values
    nlp_processor.extract_entities.return_value = [
        Entity(text="user.a@example.com", type="EMAIL"),
        Entity(text="user.b@example.com", type="EMAIL")
    ]
    nlp_processor.analyze_sentiment.return_value = MockSentiment
    voice_matcher.identify_speaker.return_value = MockVoiceMatch
    
    return ai_core, nlp_processor, arg_service, voice_matcher

@pytest.fixture
def comint_module(mock_dependencies):
    """Initializes COMINTModule with mocked dependencies."""
    return COMINTModule(*mock_dependencies)

@pytest.fixture
def mock_pcap_packets():
    """
    Creates a list of mock Scapy packets, including
    an out-of-order TCP stream.
    """
    test_time = datetime.now().timestamp()
    
    # 1. A text stream (e.g., SMTP) - 3 packets, out of order
    payload_1 = b"From: User A <user.a@example.com>\nTo: User B <user.b@example.com>\n"
    payload_2 = b"Subject: Test\n\nHello."
    payload_3 = b"This is the middle part.\n" # Out of order
    
    stream_src_ip = "1.1.1.1"
    stream_dst_ip = "2.2.2.2"
    stream_sport = 1000
    stream_dport = 25
    
    # Packet 1 (Seq 0)
    text_packet_1 = Ether()/IP(src=stream_src_ip, dst=stream_dst_ip)/TCP(sport=stream_sport, dport=stream_dport, seq=0)/Raw(load=payload_1)
    text_packet_1.time = test_time
    
    # Packet 3 (Seq 100) - Comes *before* packet 2 in list
    text_packet_3 = Ether()/IP(src=stream_src_ip, dst=stream_dst_ip)/TCP(sport=stream_sport, dport=stream_dport, seq=100)/Raw(load=payload_3)
    text_packet_3.time = test_time + 1

    # Packet 2 (Seq 50)
    text_packet_2 = Ether()/IP(src=stream_src_ip, dst=stream_dst_ip)/TCP(sport=stream_sport, dport=stream_dport, seq=50)/Raw(load=payload_2)
    text_packet_2.time = test_time + 2


    # 2. An audio packet (RTP)
    audio_payload = b'\x80\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Dummy RTP payload
    audio_packet = Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/UDP(sport=3000, dport=4000)/RTP(payload=audio_payload)
    audio_packet.time = test_time + 3

    # 3. A non-text TCP packet (e.g., binary data)
    binary_payload = b"\xDE\xAD\xBE\xEF\x01\x02\x03\xFF\xFE"
    binary_packet = Ether()/IP(src="5.5.5.5", dst="6.6.6.6")/TCP(sport=1234, dport=443)/Raw(load=binary_payload)
    binary_packet.time = test_time + 4

    return [text_packet_1, text_packet_3, text_packet_2, audio_packet, binary_packet]

def test_module_initialization(comint_module, mock_dependencies):
    """Test if the COMINTModule initializes correctly."""
    ai_core, nlp, graph, voice = mock_dependencies
    assert comint_module.ai_core == ai_core
    assert comint_module.nlp == nlp
    assert comint_module.graph == graph
    assert comint_module.voice_matcher == voice

@patch('chimera_intel.core.comint.rdpcap')
def test_process_pcap_stream_reassembly_and_text_analysis(mock_rdpcap, comint_module, mock_dependencies, mock_pcap_packets):
    """Test that text payloads are correctly reassembled, analyzed, and correlated."""
    ai_core, nlp, graph, voice = mock_dependencies
    mock_rdpcap.return_value = mock_pcap_packets
    
    # This is the expected reassembled payload, in correct sequence order
    expected_reassembled_payload = (
        b"From: User A <user.a@example.com>\nTo: User B <user.b@example.com>\n"
        b"Subject: Test\n\nHello."
        b"This is the middle part.\n"
    ).decode('utf-8')

    results = comint_module.process_pcap("dummy.pcap")
    
    assert results['packet_count'] == 5
    # Should find 1 text stream (the binary one is skipped)
    assert len(results['text_analyses']) == 1
    
    # Check NLP calls were made with the *correctly reassembled* payload
    nlp.extract_entities.assert_called_with(expected_reassembled_payload)
    nlp.analyze_sentiment.assert_called_with(expected_reassembled_payload)
    
    # Check graph correlation uses the regex-extracted emails
    graph.add_edge.assert_called_with(
        "user.a@example.com", # Extracted by regex
        "user.b@example.com", # Extracted by regex
        "COMMUNICATED_WITH",
        properties=ANY  # Check that properties were passed
    )

@patch('chimera_intel.core.comint.rdpcap')
def test_process_pcap_audio_analysis(mock_rdpcap, comint_module, mock_dependencies, mock_pcap_packets):
    """Test that audio payloads are analyzed and correlated."""
    ai_core, nlp, graph, voice = mock_dependencies
    mock_rdpcap.return_value = mock_pcap_packets

    results = comint_module.process_pcap("dummy.pcap")

    assert results['packet_count'] == 5
    assert len(results['audio_analyses']) == 1

    # Check voice matcher call
    audio_packet = mock_pcap_packets[3] # Audio packet is 4th in list
    audio_payload_bytes = audio_packet[RTP].load
    voice.identify_speaker.assert_called_with(audio_payload_bytes)

    # Check graph correlation
    graph.add_node_if_not_exists.assert_any_call("3.3.3.3", "IP_Address", {"ip": "3.3.3.3"})
    graph.add_node_if_not_exists.assert_any_call("Adversary_X", "Adversary", {"id": "Adversary_X"})
    graph.add_edge.assert_called_with(
        "3.3.3.3",
        "Adversary_X",
        "ASSOCIATED_WITH_VOICE",
        properties=ANY
    )

@patch('chimera_intel.core.comint.rdpcap')
def test_pcap_file_not_found(mock_rdpcap, comint_module):
    """Test handling of a missing PCAP file."""
    mock_rdpcap.side_effect = FileNotFoundError("File not found")
    
    with pytest.raises(FileNotFoundError):
        comint_module.process_pcap("non_existent_file.pcap")