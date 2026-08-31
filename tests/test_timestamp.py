"""Unit tests for TimestampParser."""

from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.timestamp import TimestampParser

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_timestamp_windows_firewall_composite():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    ts_parser = TimestampParser(config)

    parsed = {
        "raw_date": "2026-08-27",
        "raw_time": "09:02:11",
    }
    event_time = ts_parser.parse_time(parsed)
    assert event_time == "2026-08-27T09:02:11Z"


def test_timestamp_palo_alto():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Palo Alto Networks", "PAN-OS")
    ts_parser = TimestampParser(config)

    parsed = {
        "raw_generate_time": "2026/08/31 15:40:12",
    }
    event_time = ts_parser.parse_time(parsed)
    assert event_time == "2026-08-31T15:40:12Z"


def test_timestamp_cisco_asa():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    ts_parser = TimestampParser(config)

    parsed = {
        "raw_timestamp": "Aug 31 2026 15:45:01",
    }
    event_time = ts_parser.parse_time(parsed)
    assert event_time == "2026-08-31T15:45:01Z"


def test_timestamp_suricata_iso():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("OISF", "Suricata")
    ts_parser = TimestampParser(config)

    parsed = {
        "raw_timestamp": "2026-08-31T15:58:10.001234+0000",
    }
    event_time = ts_parser.parse_time(parsed)
    assert event_time == "2026-08-31T15:58:10.001234Z"
