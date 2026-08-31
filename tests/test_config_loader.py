"""Unit tests for ConfigLoader and MappingConfig."""

import pytest
from pathlib import Path
from src.engine.config_loader import ConfigLoader, MappingConfig, MappingConfigError

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_load_all_configs():
    loader = ConfigLoader(MAPPINGS_DIR)
    assert len(loader) >= 4

    vendors = [cfg.vendor for cfg in loader]
    assert "Microsoft" in vendors
    assert "Cisco" in vendors
    assert "Palo Alto Networks" in vendors
    assert "OISF" in vendors


def test_windows_firewall_config():
    loader = ConfigLoader(MAPPINGS_DIR)
    cfg = loader.get_by_source("Microsoft", "Windows Firewall")
    assert cfg is not None
    assert cfg.format == "space_delimited"
    assert cfg.detection_method == "regex"
    assert "pattern" in cfg.detection
    assert cfg.default_class_uid == 4001
    assert len(cfg.classification_rules) == 2
    assert "raw_src_ip" in cfg.field_map
    assert cfg.static_fields.get("device.vendor_name") == "Microsoft"
    assert "raw_direction" in cfg.transforms
    assert cfg.raw_preservation.get("enabled") is True


def test_cisco_asa_config():
    loader = ConfigLoader(MAPPINGS_DIR)
    cfg = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    assert cfg is not None
    assert cfg.format == "syslog"
    assert cfg.detection_method == "regex"
    assert "message_families" in cfg.raw_config
    assert "connection" in cfg.message_families
    assert len(cfg.classification_rules) >= 4
    assert cfg.raw_preservation.get("target_field") == "raw_data"


def test_palo_alto_config():
    loader = ConfigLoader(MAPPINGS_DIR)
    cfg = loader.get_by_source("Palo Alto Networks", "PAN-OS")
    assert cfg is not None
    assert cfg.format == "csv"
    assert cfg.detection_method == "csv_header_and_field"
    assert len(cfg.classification_rules) >= 4
    assert "raw_src_ip" in cfg.field_map


def test_suricata_config():
    loader = ConfigLoader(MAPPINGS_DIR)
    cfg = loader.get_by_source("OISF", "Suricata")
    assert cfg is not None
    assert cfg.format == "json"
    assert cfg.detection_method == "json_match"
    assert len(cfg.classification_rules) == 2
    assert "raw_src_ip" in cfg.field_map


def test_invalid_config_validation():
    # Missing required sections
    with pytest.raises(MappingConfigError):
        MappingConfig({"source_identity": {"vendor": "Test"}})

    # Missing vendor in source_identity
    with pytest.raises(MappingConfigError):
        MappingConfig({
            "source_identity": {},
            "detection": {},
            "parsing": {},
            "classification": {},
            "field_map": {},
        })
