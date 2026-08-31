"""Unit tests for ValueTransformer."""

from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.transforms import ValueTransformer

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_windows_firewall_transforms():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    transformer = ValueTransformer(config)

    parsed = {
        "raw_direction": "RECEIVE",
        "raw_protocol": "tcp",
    }
    transformed = transformer.transform_all(parsed)

    assert transformed["raw_direction"] == "Inbound"
    assert transformed["raw_protocol"] == "TCP"


def test_palo_alto_integer_transforms():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Palo Alto Networks", "PAN-OS")
    transformer = ValueTransformer(config)

    parsed = {
        "raw_src_port": "61043",
        "raw_dst_port": "443",
        "raw_bytes": "451200",
        "raw_protocol": "TCP",
    }
    transformed = transformer.transform_all(parsed)

    assert transformed["raw_src_port"] == 61043
    assert transformed["raw_dst_port"] == 443
    assert transformed["raw_bytes"] == 451200
    assert transformed["raw_protocol"] == "tcp"


def test_cisco_asa_duration_transform():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    transformer = ValueTransformer(config)

    parsed = {
        "raw_duration": "0:00:44",
        "raw_bytes": "5420",
        "raw_severity": "6",
    }
    transformed = transformer.transform_all(parsed)

    assert transformed["raw_duration"] == 44
    assert transformed["raw_bytes"] == 5420
    assert transformed["raw_severity"] == 6


def test_protocol_num_and_severity():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    transformer = ValueTransformer(config)

    # Test protocol number conversion
    assert transformer.apply_transform("protocol_num_to_name", "6", {}) == "TCP"
    assert transformer.apply_transform("protocol_num_to_name", "17", {}) == "UDP"
    assert transformer.apply_transform("protocol_num_to_name", "1", {}) == "ICMP"

    # Test severity lookup
    assert transformer.apply_transform("severity_lookup", "1", {}) == "Informational"
    assert transformer.apply_transform("severity_lookup", "high", {}) == "High"
    assert transformer.apply_transform("severity_lookup", "critical", {}) == "Critical"
