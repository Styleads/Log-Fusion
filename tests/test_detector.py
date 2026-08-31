"""Tests for automatic log detection across all sample sources."""

from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.detector import LogDetector

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_detect_windows_firewall():
    loader = ConfigLoader(MAPPINGS_DIR)
    detector = LogDetector(loader)

    line = "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389 0 S 3421552 0 8192 - - - RECEIVE"
    matched = detector.detect(line)
    assert matched is not None
    assert matched.vendor == "Microsoft"
    assert matched.product == "Windows Firewall"


def test_detect_cisco_asa():
    loader = ConfigLoader(MAPPINGS_DIR)
    detector = LogDetector(loader)

    line = "Aug 31 2026 15:45:01: %ASA-6-302013: Built outbound TCP connection 104521 for outside:142.250.190.46/443 (142.250.190.46/443) to inside:192.168.1.105/51220 (203.0.113.10/15220)"
    matched = detector.detect(line)
    assert matched is not None
    assert matched.vendor == "Cisco"
    assert matched.product == "Adaptive Security Appliance"


def test_detect_suricata_eve_json():
    loader = ConfigLoader(MAPPINGS_DIR)
    detector = LogDetector(loader)

    line = '{"timestamp":"2026-08-31T15:58:10.001234+0000","flow_id":14023948102394,"in_iface":"eth1","event_type":"alert","src_ip":"192.168.1.105","src_port":49221,"dest_ip":"185.220.101.5","dest_port":6667,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2017321,"rev":3,"signature":"ET MALWARE IRC Botnet Command and Control Activity","category":"A Network Trojan was detected","severity":1},"flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":240,"bytes_toclient":180,"start":"2026-08-31T15:58:09.551221+0000"}}'
    matched = detector.detect(line)
    assert matched is not None
    assert matched.vendor == "OISF"
    assert matched.product == "Suricata"


def test_detect_palo_alto_csv_header():
    loader = ConfigLoader(MAPPINGS_DIR)
    detector = LogDetector(loader)

    header_line = '"FUTURE_USE","Receive Time","Serial Number","Type","Subtype","Version","Generate Time","Source IP","Destination IP"'
    matched = detector.detect(header_line)
    assert matched is not None
    assert matched.vendor == "Palo Alto Networks"
