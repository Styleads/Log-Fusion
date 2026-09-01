"""Comprehensive test suite for the Auto-Mapping Assistant."""

import json
import shutil
import tempfile
from pathlib import Path
import pytest
import yaml
from fastapi.testclient import TestClient

from src.assistant.detector_heuristics import FormatDetector
from src.assistant.semantic_analyzer import SemanticAnalyzer
from src.assistant.generator import YamlGenerator
from src.assistant.validator import DraftValidator
from src.assistant.service import AutoMappingAssistant, slugify
from src.assistant.llm_fallback import OllamaFallback
from src.app.main2 import app
from src.engine.pipeline import NormalizationPipeline


@pytest.fixture
def temp_mappings_dir():
    """Create a temporary mappings directory for test isolation."""
    temp_dir = tempfile.mkdtemp(prefix="ulpf_test_mappings_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


# ==========================================
# 1. Format Detection Tests
# ==========================================

def test_detect_space_delimited():
    detector = FormatDetector()
    lines = [
        "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389",
        "2026-08-27 09:02:12 ALLOW TCP 192.168.1.50 10.0.0.14 44321 443",
        "2026-08-27 09:02:15 DROP UDP 198.51.100.22 10.0.0.14 12345 53",
    ]
    res = detector.detect(lines)
    assert res.format_type == "space_delimited"
    assert res.delimiter == " "
    assert res.confidence >= 0.7
    assert len(res.parsed_samples) == 3


def test_detect_key_value():
    detector = FormatDetector()
    lines = [
        'date=2026-08-27 time=09:14:02 devname="fw-edge-01" action="deny" proto=6 srcip=203.0.113.45 dstip=10.0.4.12 srcport=51322 dstport=22',
        'date=2026-08-27 time=09:14:05 devname="fw-edge-01" action="allow" proto=6 srcip=192.168.1.10 dstip=10.0.4.12 srcport=43211 dstport=443',
    ]
    res = detector.detect(lines)
    assert res.format_type == "key_value"
    assert res.confidence >= 0.8
    assert "srcip" in res.parsed_samples[0]
    assert res.parsed_samples[0]["action"] == "deny"


def test_detect_json():
    detector = FormatDetector()
    lines = [
        json.dumps({
            "timestamp": "2026-08-27T09:14:02.123456Z",
            "event_type": "alert",
            "src_ip": "198.51.100.45",
            "src_port": 49152,
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {"action": "blocked", "signature": "ET SCAN Nmap Scripting Engine"}
        }),
        json.dumps({
            "timestamp": "2026-08-27T09:14:05.654321Z",
            "event_type": "alert",
            "src_ip": "198.51.100.46",
            "src_port": 49153,
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {"action": "allowed", "signature": "ET INFO TLS Handshake"}
        }),
    ]
    res = detector.detect(lines)
    assert res.format_type == "json"
    assert res.detection_method == "json_match"
    assert res.confidence >= 0.9
    assert len(res.parsed_samples) == 2


def test_detect_csv_with_headers():
    detector = FormatDetector()
    lines = [
        '"Time","Action","Protocol","Source IP","Destination IP","Source Port","Destination Port"',
        '"2026-08-27 09:14:02","deny","TCP","203.0.113.45","10.0.4.12","51322","22"',
        '"2026-08-27 09:14:05","allow","TCP","192.168.1.10","10.0.4.12","43211","443"',
    ]
    res = detector.detect(lines)
    assert res.format_type == "csv"
    assert res.has_header is True
    assert res.header_columns is not None
    assert "source_ip" in res.header_columns


# ==========================================
# 2. Semantic Analyzer Tests
# ==========================================

def test_semantic_analysis_space_delimited():
    detector = FormatDetector()
    analyzer = SemanticAnalyzer()

    lines = [
        "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389",
        "2026-08-27 09:02:12 ALLOW TCP 192.168.1.50 10.0.0.14 44321 443",
    ]
    fmt = detector.detect(lines)
    sem = analyzer.analyze(fmt, source_name="Test Edge FW", device_type_hint="firewall")

    assert sem.confidence_label in ("high", "medium")
    assert "src_endpoint.ip" in sem.field_map.values()
    assert "dst_endpoint.ip" in sem.field_map.values()
    assert "src_endpoint.port" in sem.field_map.values()
    assert "dst_endpoint.port" in sem.field_map.values()
    assert "connection_info.protocol_name" in sem.field_map.values()
    assert sem.default_class_uid == 4001
    assert len(sem.classification_rules) >= 1
    # Check that ports have integer transform
    assert any(t.get("type") == "integer" for t in sem.transforms.values())


def test_semantic_analysis_key_value():
    detector = FormatDetector()
    analyzer = SemanticAnalyzer()

    lines = [
        'date=2026-08-27 time=09:14:02 devname="fw01" action="deny" proto=TCP srcip=203.0.113.45 dstip=10.0.4.12 sport=51322 dport=22',
    ]
    fmt = detector.detect(lines)
    sem = analyzer.analyze(fmt, source_name="SonicWall", device_type_hint="firewall")

    assert "src_endpoint.ip" in sem.field_map.values()
    assert "dst_endpoint.ip" in sem.field_map.values()
    assert "src_endpoint.port" in sem.field_map.values()
    assert "dst_endpoint.port" in sem.field_map.values()


# ==========================================
# 3. YAML Generator Tests
# ==========================================

def test_yaml_generation_structure():
    detector = FormatDetector()
    analyzer = SemanticAnalyzer()
    generator = YamlGenerator()

    lines = [
        "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389",
    ]
    fmt = detector.detect(lines)
    sem = analyzer.analyze(fmt, source_name="Sample Firewall")
    yaml_str = generator.generate_yaml(fmt, sem, source_name="Sample Firewall")

    # Verify Header Comment
    assert "# ⚠️ AUTO-GENERATED DRAFT" in yaml_str
    assert "# Generated by: Auto-Mapping Assistant" in yaml_str
    assert "remove this header and move status to" in yaml_str

    # Verify YAML is parseable
    parsed = yaml.safe_load(yaml_str)
    assert isinstance(parsed, dict)
    assert parsed["source_identity"]["status"] == "draft"
    assert parsed["source_identity"]["vendor"] == "Sample Firewall"
    assert "detection" in parsed
    assert "parsing" in parsed
    assert "classification" in parsed
    assert "field_map" in parsed
    assert "static_fields" in parsed
    assert "transforms" in parsed
    assert "timestamp" in parsed
    assert "unmapped_policy" in parsed
    assert "raw_preservation" in parsed


# ==========================================
# 4. Draft Validator & Pipeline Execution Tests
# ==========================================

def test_draft_validator_space_delimited_end_to_end():
    assistant = AutoMappingAssistant()
    sample_lines = [
        "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389",
        "2026-08-27 09:02:15 ALLOW TCP 192.168.1.50 10.0.0.14 44321 443",
    ]

    analysis = assistant.analyze("Edge Firewall", sample_lines)

    assert analysis["validation"]["valid"] is True
    assert analysis["validation"]["successful_events"] == 2
    assert len(analysis["ocsf_preview"]) == 2

    event = analysis["ocsf_preview"][0]
    assert event["raw_data"] == sample_lines[0]
    assert "metadata" in event and "uid" in event["metadata"]
    assert event.get("src_endpoint", {}).get("ip") == "45.33.32.156"
    assert event.get("dst_endpoint", {}).get("ip") == "10.0.0.14"
    assert event.get("src_endpoint", {}).get("port") == 51322
    assert event.get("dst_endpoint", {}).get("port") == 3389
    assert event.get("connection_info", {}).get("protocol_name") == "TCP"
    assert event.get("activity_name") == "Deny"


def test_draft_validator_key_value_end_to_end():
    assistant = AutoMappingAssistant()
    sample_lines = [
        'date=2026-08-27 time=09:14:02 devname="fw-edge" action="deny" proto=TCP srcip=203.0.113.45 dstip=10.0.4.12 sport=51322 dport=22',
        'date=2026-08-27 time=09:14:03 devname="fw-edge" action="allow" proto=TCP srcip=192.168.1.10 dstip=10.0.4.12 sport=43211 dport=443',
    ]

    analysis = assistant.analyze("Fortinet FortiOS", sample_lines)

    assert analysis["validation"]["valid"] is True
    assert analysis["validation"]["successful_events"] == 2
    event = analysis["ocsf_preview"][0]
    assert event.get("src_endpoint", {}).get("ip") == "203.0.113.45"
    assert event.get("dst_endpoint", {}).get("ip") == "10.0.4.12"
    assert event.get("src_endpoint", {}).get("port") == 51322
    assert event.get("dst_endpoint", {}).get("port") == 22


# ==========================================
# 5. Service Persistence, Collision & Approval Tests
# ==========================================

def test_save_draft_and_approval_flow(temp_mappings_dir):
    assistant = AutoMappingAssistant(mappings_dir=temp_mappings_dir)

    sample_lines = [
        "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389"
    ]
    analysis = assistant.analyze("Router ACL", sample_lines)

    # 1. Save draft
    save_res = assistant.save_draft(
        source_name="Router ACL",
        yaml_content=analysis["yaml_draft"],
        raw_lines=sample_lines,
    )
    assert save_res["status"] == "saved"
    slug = save_res["slug"]
    assert slug == "router_acl"

    yaml_path = Path(save_res["yaml_file"])
    sample_path = Path(save_res["sample_file"])
    assert yaml_path.exists()
    assert sample_path.exists()

    # 2. List drafts
    drafts = assistant.list_drafts()
    assert len(drafts) == 1
    assert drafts[0]["slug"] == "router_acl"
    assert drafts[0]["status"] == "draft"

    # 3. Approve draft
    appr_res = assistant.approve_draft("router_acl")
    assert appr_res["status"] == "approved"

    # Verify status changed in file and header updated
    with open(yaml_path, "r", encoding="utf-8") as f:
        content = f.read()
        data = yaml.safe_load(content)
        assert data["source_identity"]["status"] == "reviewed"
        assert "# Status: Reviewed & Approved" in content
        assert "# ⚠️ AUTO-GENERATED DRAFT" not in content

    # 4. Drafts list should now be empty
    drafts_after = assistant.list_drafts()
    assert len(drafts_after) == 0


def test_save_draft_collision_protection(temp_mappings_dir):
    assistant = AutoMappingAssistant(mappings_dir=temp_mappings_dir)
    sample_lines = ["2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389"]

    analysis = assistant.analyze("Test Vendor", sample_lines)
    # 1. Save and approve first version
    assistant.save_draft("Test Vendor", analysis["yaml_draft"], sample_lines)
    assistant.approve_draft("test_vendor")

    # 2. Save another draft with the same vendor name -> should create non-colliding slug
    save_res_2 = assistant.save_draft("Test Vendor", analysis["yaml_draft"], sample_lines)
    assert save_res_2["slug"] == "test_vendor_2"


# ==========================================
# 6. LLM Fallback Offline Graceful Handling
# ==========================================

def test_llm_fallback_offline_graceful():
    fallback = OllamaFallback(endpoint="http://127.0.0.1:59999/api/generate", timeout=0.1)
    assert fallback.is_available() is False
    mappings = fallback.suggest_mappings(["2026-08-27 sample"], ["unknown_col"], {})
    assert mappings == {}


# ==========================================
# 7. FastAPI Endpoint Tests
# ==========================================

def test_api_endpoints():
    client = TestClient(app)

    # Health Check
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"

    # Assistant Analyze Endpoint
    payload = {
        "source_name": "API Test Firewall",
        "raw_lines": [
            "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389",
            "2026-08-27 09:02:15 ALLOW TCP 192.168.1.50 10.0.0.14 44321 443"
        ],
        "device_type": "firewall"
    }
    resp = client.post("/api/v1/assistant/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["data"]["validation"]["valid"] is True
    assert len(data["data"]["ocsf_preview"]) == 2

    # Assistant Drafts List Endpoint
    drafts_resp = client.get("/api/v1/assistant/drafts")
    assert drafts_resp.status_code == 200
    assert "drafts" in drafts_resp.json()
