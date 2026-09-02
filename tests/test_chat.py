"""Tests for the RAG Chatbot /api/v1/chat endpoint and telemetry classification."""

import pytest
from fastapi.testclient import TestClient
from src.app.main import app, is_denied_event, is_allowed_event


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_76_events():
    """Generates 76 normalized OCSF events: 50 allowed, 20 denied, 6 findings."""
    events = []
    # 50 Allowed events
    for i in range(50):
        events.append({
            "metadata": {"uid": f"allow-{i}"},
            "class_name": "Network Activity",
            "class_uid": 4001,
            "activity_name": "Allow",
            "activity_id": 1,
            "time": "2026-09-01T10:00:00Z",
            "src_endpoint": {"ip": f"192.168.1.{10 + (i % 10)}", "port": 40000 + i},
            "dst_endpoint": {"ip": "10.0.0.5", "port": 443},
            "device": {"vendor_name": "Palo Alto Networks"},
            "raw_data": f"sample allow line {i}",
        })
    # 20 Denied events
    for i in range(20):
        events.append({
            "metadata": {"uid": f"deny-{i}"},
            "class_name": "Network Activity",
            "class_uid": 4001,
            "activity_name": "Deny",
            "activity_id": 6,
            "time": "2026-09-01T10:05:00Z",
            "src_endpoint": {"ip": "203.0.113.45" if i < 15 else "198.51.100.22", "port": 50000 + i},
            "dst_endpoint": {"ip": "10.0.4.12", "port": 22},
            "device": {"vendor_name": "Cisco ASA"},
            "raw_data": f"sample drop line {i}",
        })
    # 6 Detection Findings
    for i in range(6):
        events.append({
            "metadata": {"uid": f"finding-{i}"},
            "class_name": "Detection Finding",
            "class_uid": 2001,
            "severity": "High",
            "time": "2026-09-01T10:10:00Z",
            "src_endpoint": {"ip": "185.220.101.4", "port": 45000 + i},
            "dst_endpoint": {"ip": "10.0.4.30", "port": 22},
            "finding_info": {"title": f"ET SCAN Potential SSH Scan {i}"},
            "device": {"vendor_name": "Suricata IDS"},
            "raw_data": f"sample alert line {i}",
        })
    return events


def test_is_allowed_and_denied_helpers():
    allowed_ev = {"activity_name": "Allow", "activity_id": 1}
    denied_ev = {"activity_name": "Deny", "activity_id": 6}
    drop_ev = {"raw_data": "2026-09-01 DROP TCP 1.2.3.4"}
    
    assert is_allowed_event(allowed_ev) is True
    assert is_denied_event(allowed_ev) is False
    assert is_denied_event(denied_ev) is True
    assert is_allowed_event(denied_ev) is False
    assert is_denied_event(drop_ev) is True


def test_chat_inspects_all_76_events(client, sample_76_events):
    resp = client.post("/api/v1/chat", json={
        "prompt": "how many allowed requests?",
        "context_events": sample_76_events,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["structuredData"]["totalAnalyzed"] == 76
    assert data["structuredData"]["allowedCount"] == 50
    assert "50" in data["text"]
    assert len(data["citations"]) > 0


def test_chat_blocked_requests(client, sample_76_events):
    resp = client.post("/api/v1/chat", json={
        "prompt": "how many blocked requests?",
        "context_events": sample_76_events,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["structuredData"]["totalAnalyzed"] == 76
    assert data["structuredData"]["deniedCount"] == 20
    assert "20" in data["text"]


def test_chat_total_summary(client, sample_76_events):
    resp = client.post("/api/v1/chat", json={
        "prompt": "how many total events in the datastore?",
        "context_events": sample_76_events,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["structuredData"]["totalAnalyzed"] == 76
    assert "76" in data["text"]


def test_chat_detection_findings(client, sample_76_events):
    resp = client.post("/api/v1/chat", json={
        "prompt": "what are the active threat alerts or detection findings?",
        "context_events": sample_76_events,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["structuredData"]["findingsCount"] == 6
    assert "6" in data["text"] or "ET SCAN" in data["text"] or len(data["citations"]) > 0


def test_chat_trojan_detected(client):
    trojan_event = {
        "metadata": {"uid": "trojan-001"},
        "class_name": "Network Detection",
        "class_uid": 2001,
        "activity_name": "Alert Allowed",
        "time": "2026-08-31T15:58:10.001234Z",
        "src_endpoint": {"ip": "192.168.1.105", "port": 49221},
        "dst_endpoint": {"ip": "185.220.101.5", "port": 6667},
        "device": {"vendor_name": "OISF", "product": {"name": "Suricata"}},
        "detection": {
            "signature": "ET MALWARE IRC Botnet Command and Control Activity",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "signature_id": 2017321,
            "action": "allowed"
        },
        "raw_data": '{"timestamp":"2026-08-31T15:58:10.001234+0000","alert":{"signature":"ET MALWARE IRC Botnet Command and Control Activity","category":"A Network Trojan was detected","severity":1}}'
    }

    resp = client.post("/api/v1/chat", json={
        "prompt": "was any trojan detected?",
        "context_events": [trojan_event],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "yes" in data["text"].lower() or "trojan" in data["text"].lower()
    assert "192.168.1.105" in data["text"] or "185.220.101.5" in data["text"] or len(data["citations"]) > 0


def test_chat_trojans_plural_detected(client):
    trojan_event = {
        "metadata": {"uid": "trojan-001"},
        "class_name": "Network Detection",
        "class_uid": 2001,
        "activity_name": "Alert Allowed",
        "time": "2026-08-31T15:58:10.001234Z",
        "src_endpoint": {"ip": "192.168.1.105", "port": 49221},
        "dst_endpoint": {"ip": "185.220.101.5", "port": 6667},
        "device": {"vendor_name": "OISF", "product": {"name": "Suricata"}},
        "detection": {
            "signature": "ET MALWARE IRC Botnet Command and Control Activity",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "signature_id": 2017321,
            "action": "allowed"
        },
        "raw_data": '{"timestamp":"2026-08-31T15:58:10.001234+0000","alert":{"signature":"ET MALWARE IRC Botnet Command and Control Activity","category":"A Network Trojan was detected","severity":1}}'
    }

    resp = client.post("/api/v1/chat", json={
        "prompt": "any trojans detected?",
        "context_events": [trojan_event],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "yes" in data["text"].lower() or "trojan" in data["text"].lower()
    assert data["structuredData"]["matchedCount"] >= 1
    assert data["citations"][0]["event_uid"] == "trojan-001"


def test_chat_ransomware_negative(client, sample_76_events):
    resp = client.post("/api/v1/chat", json={
        "prompt": "was any ransomware detected?",
        "context_events": sample_76_events,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "no" in data["text"].lower() or "0" in data["text"] or "zero" in data["text"].lower()



