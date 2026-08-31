"""Unit tests for NestedMapper and dotted-path helper."""

from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.mapper import NestedMapper, set_nested_value, get_nested_value

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_set_and_get_nested_value():
    d = {}
    set_nested_value(d, "src_endpoint.ip", "192.168.1.100")
    set_nested_value(d, "src_endpoint.port", 8080)
    set_nested_value(d, "metadata.product.name", "TestApp")

    assert d == {
        "src_endpoint": {
            "ip": "192.168.1.100",
            "port": 8080,
        },
        "metadata": {
            "product": {
                "name": "TestApp",
            }
        }
    }

    assert get_nested_value(d, "src_endpoint.ip") == "192.168.1.100"
    assert get_nested_value(d, "src_endpoint.port") == 8080
    assert get_nested_value(d, "metadata.product.name") == "TestApp"
    assert get_nested_value(d, "nonexistent.path") is None


def test_mapper_windows_firewall():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    mapper = NestedMapper(config)

    parsed = {
        "raw_src_ip": "45.33.32.156",
        "raw_dst_ip": "10.0.0.14",
        "raw_src_port": 51322,
        "raw_dst_port": 3389,
        "raw_protocol": "TCP",
        "raw_size": 0,
        "tcpflags": "S",
        "tcpsyn": "3421552",
    }
    classification = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "activity_id": 6,
        "activity_name": "Deny",
    }

    event = mapper.map_event(
        parsed_fields=parsed,
        classification=classification,
        event_time="2026-08-27T09:02:11Z",
    )

    # Verify classification
    assert event["class_uid"] == 4001
    assert event["class_name"] == "Network Activity"
    assert event["activity_id"] == 6
    assert event["activity_name"] == "Deny"
    assert event["time"] == "2026-08-27T09:02:11Z"

    # Verify static fields
    assert event["device"]["vendor_name"] == "Microsoft"
    assert event["device"]["type"] == "Host Firewall"
    assert event["metadata"]["product"]["name"] == "Windows Firewall"

    # Verify mapped fields
    assert event["src_endpoint"]["ip"] == "45.33.32.156"
    assert event["src_endpoint"]["port"] == 51322
    assert event["dst_endpoint"]["ip"] == "10.0.0.14"
    assert event["dst_endpoint"]["port"] == 3389
    assert event["connection_info"]["protocol_name"] == "TCP"
    assert event["traffic"]["bytes"] == 0

    # Verify unmapped bucket
    assert "unmapped" in event
    assert event["unmapped"]["tcpflags"] == "S"
    assert event["unmapped"]["tcpsyn"] == "3421552"
