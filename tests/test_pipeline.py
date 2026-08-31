"""Integration tests for the complete NormalizationPipeline."""

import json
from pathlib import Path
from src.engine.pipeline import NormalizationPipeline

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
MAPPINGS_DIR = WORKSPACE_ROOT / "mappings"


def test_windows_firewall_end_to_end():
    pipeline = NormalizationPipeline(MAPPINGS_DIR)
    sample_path = MAPPINGS_DIR / "windows_firewall" / "samples" / "windows_firewall_sample.log"

    events = pipeline.process_file(sample_path)
    # The sample file has 21 total lines, 4 header lines starting with '#', so 17 data events
    assert len(events) == 17

    first_event = events[0]

    # Check classification
    assert first_event["class_name"] == "Network Activity"
    assert first_event["class_uid"] == 4001
    assert first_event["activity_name"] == "Deny"
    assert first_event["activity_id"] == 6

    # Check time normalization
    assert first_event["time"] == "2026-08-27T09:02:11Z"

    # Check nested endpoints
    assert first_event["src_endpoint"]["ip"] == "45.33.32.156"
    assert first_event["src_endpoint"]["port"] == "51322"
    assert first_event["dst_endpoint"]["ip"] == "10.0.0.14"
    assert first_event["dst_endpoint"]["port"] == "3389"

    # Check connection info & transforms
    assert first_event["connection_info"]["protocol_name"] == "TCP"
    assert first_event["connection_info"]["direction"] == "Inbound"

    # Check static fields
    assert first_event["device"]["vendor_name"] == "Microsoft"
    assert first_event["device"]["type"] == "Host Firewall"
    assert first_event["metadata"]["product"]["vendor_name"] == "Microsoft"
    assert first_event["metadata"]["product"]["name"] == "Windows Firewall"

    # Check traceability & raw data preservation
    assert "uid" in first_event["metadata"]
    assert len(first_event["metadata"]["uid"]) == 36  # Valid UUID length
    assert first_event["raw_data"].startswith("2026-08-27 09:02:11 DROP TCP")

    # Check unmapped bucket
    assert "unmapped" in first_event
    assert first_event["unmapped"]["col_9"] == "S"


def test_cisco_asa_end_to_end():
    pipeline = NormalizationPipeline(MAPPINGS_DIR)
    sample_path = MAPPINGS_DIR / "CISCO_ASA" / "samples" / "syslog_sample.txt"

    events = pipeline.process_file(sample_path)
    assert len(events) == 4

    # Check 1st event: Built connection (302013)
    ev0 = events[0]
    assert ev0["class_name"] == "Network Activity"
    assert ev0["class_uid"] == 4001
    assert ev0["activity_name"] == "Open"
    assert ev0["src_endpoint"]["ip"] == "142.250.190.46"
    assert ev0["src_endpoint"]["port"] == 443
    assert ev0["dst_endpoint"]["ip"] == "192.168.1.105"
    assert ev0["dst_endpoint"]["port"] == 51220
    assert ev0["connection_info"]["protocol_name"] == "TCP"
    assert ev0["device"]["vendor_name"] == "Cisco"
    assert "uid" in ev0["metadata"]
    assert ev0["raw_data"].startswith("Aug 31 2026 15:45:01: %ASA-6-302013")

    # Check 2nd event: Deny (106023)
    ev1 = events[1]
    assert ev1["class_name"] == "Network Activity"
    assert ev1["activity_name"] == "Refuse"
    assert ev1["src_endpoint"]["ip"] == "45.227.254.12"
    assert ev1["dst_endpoint"]["ip"] == "192.168.1.50"
    assert ev1["policy"]["name"] == "OUTSIDE_IN"


def test_palo_alto_end_to_end():
    pipeline = NormalizationPipeline(MAPPINGS_DIR)
    sample_path = MAPPINGS_DIR / "Palo_Alto" / "samples" / "PaloAlto_sample.csv"

    events = pipeline.process_file(sample_path)
    assert len(events) == 3

    ev0 = events[0]
    assert ev0["class_name"] == "Network Activity"
    assert ev0["activity_name"] == "Allow"
    assert ev0["src_endpoint"]["ip"] == "192.168.1.142"
    assert ev0["src_endpoint"]["port"] == 61043
    assert ev0["dst_endpoint"]["ip"] == "52.113.194.132"
    assert ev0["dst_endpoint"]["port"] == 443
    assert ev0["device"]["vendor_name"] == "Palo Alto Networks"
    assert ev0["traffic"]["bytes"] == 451200
    assert "uid" in ev0["metadata"]
    assert "raw_data" in ev0


def test_suricata_end_to_end():
    pipeline = NormalizationPipeline(MAPPINGS_DIR)
    sample_path = MAPPINGS_DIR / "Suricata_IDS" / "samples" / "ids_sample.json"

    events = pipeline.process_file(sample_path)
    assert len(events) == 3

    ev0 = events[0]
    assert ev0["class_name"] == "Network Detection"
    assert ev0["activity_name"] == "Alert Allowed"
    assert ev0["src_endpoint"]["ip"] == "192.168.1.105"
    assert ev0["src_endpoint"]["port"] == 49221
    assert ev0["dst_endpoint"]["ip"] == "185.220.101.5"
    assert ev0["dst_endpoint"]["port"] == 6667
    assert ev0["detection"]["signature"] == "ET MALWARE IRC Botnet Command and Control Activity"
    assert ev0["detection"]["severity"] == 1
    assert ev0["traffic"]["bytes_to_server"] == 240
    assert ev0["device"]["vendor_name"] == "OISF"
    assert "uid" in ev0["metadata"]
    assert "raw_data" in ev0
