"""Unit tests for OCSFClassifier."""

from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.classifier import OCSFClassifier

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_classify_windows_firewall_drop():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    classifier = OCSFClassifier(config)

    parsed = {"raw_action": "DROP", "raw_protocol": "TCP"}
    res = classifier.classify(parsed)

    assert res["class_uid"] == 4001
    assert res["class_name"] == "Network Activity"
    assert res["activity_id"] == 6
    assert res["activity_name"] == "Deny"


def test_classify_windows_firewall_allow():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    classifier = OCSFClassifier(config)

    parsed = {"raw_action": "ALLOW", "raw_protocol": "TCP"}
    res = classifier.classify(parsed)

    assert res["class_uid"] == 4001
    assert res["class_name"] == "Network Activity"
    assert res["activity_id"] == 1
    assert res["activity_name"] == "Allow"


def test_classify_cisco_asa_connection():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    classifier = OCSFClassifier(config)

    parsed = {"message_family": "connection", "event_action": "open"}
    res = classifier.classify(parsed)

    assert res["class_name"] == "Network Activity"
    assert res["activity_name"] == "Open"
    assert res["class_uid"] == 4001


def test_classify_cisco_asa_access_denied():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    classifier = OCSFClassifier(config)

    parsed = {"message_family": "access_control", "event_action": "deny"}
    res = classifier.classify(parsed)

    assert res["activity_name"] == "Refuse"
    assert res["class_uid"] == 4001


def test_classify_suricata_alert():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("OISF", "Suricata")
    classifier = OCSFClassifier(config)

    parsed = {"raw_event_type": "alert", "raw_alert_action": "blocked"}
    res = classifier.classify(parsed)

    assert res["class_name"] == "Network Detection"
    assert res["activity_name"] == "Alert Blocked"
    assert res["class_uid"] == 2001


def test_classify_predicate_contains():
    from src.engine.config_loader import MappingConfig
    cfg = MappingConfig({
        "source_identity": {"vendor": "Test", "product": "Test", "format": "json", "version": "1.0"},
        "detection": {"method": "regex", "pattern": ".*"},
        "parsing": {"format": "json"},
        "classification": {
            "default_class_uid": 4002,
            "default_class_name": "HTTP Activity",
            "rules": [
                {
                    "when": {"raw_result_code_contains": "DENIED"},
                    "class_uid": 4002,
                    "activity_id": 6,
                    "activity_name": "Deny",
                },
                {
                    "when": {"raw_result_code_contains": "HIT"},
                    "class_uid": 4002,
                    "activity_id": 1,
                    "activity_name": "Allow",
                }
            ]
        },
        "field_map": {},
        "static_fields": {},
        "transforms": {},
        "timestamp": {"source_field": "raw_time", "format": "%Y-%m-%d %H:%M:%S"},
        "unmapped_policy": {"action": "bucket", "target": "unmapped"},
        "raw_preservation": {"enabled": True, "target_field": "raw_data"}
    })
    classifier = OCSFClassifier(cfg)
    res_deny = classifier.classify({"raw_result_code": "TCP_DENIED/403"})
    assert res_deny["activity_name"] == "Deny"
    assert res_deny["activity_id"] == 6

    res_allow = classifier.classify({"raw_result_code": "TCP_HIT/200"})
    assert res_allow["activity_name"] == "Allow"
    assert res_allow["activity_id"] == 1

