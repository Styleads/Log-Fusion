"""Unit tests for format-specific parsers."""

import csv
import io
from pathlib import Path
from src.engine.config_loader import ConfigLoader
from src.engine.parsers import (
    DelimitedParser,
    JSONParser,
    KeyValueParser,
    SyslogParser,
    get_parser,
)

MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def test_windows_firewall_delimited_parser():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    assert config is not None
    parser = get_parser(config)
    assert isinstance(parser, DelimitedParser)

    # Comment line should return None
    assert parser.parse("#Version: 1.5") is None
    assert parser.parse("#Fields: date time action protocol...") is None

    # Data line
    sample_line = "2026-08-27 09:02:11 DROP TCP 45.33.32.156 10.0.0.14 51322 3389 0 S 3421552 0 8192 - - - RECEIVE"
    parsed = parser.parse(sample_line)
    assert parsed is not None
    assert parsed.get("raw_date") == "2026-08-27"
    assert parsed.get("raw_time") == "09:02:11"
    assert parsed.get("raw_action") == "DROP"
    assert parsed.get("raw_protocol") == "TCP"
    assert parsed.get("raw_src_ip") == "45.33.32.156"
    assert parsed.get("raw_dst_ip") == "10.0.0.14"
    assert parsed.get("raw_src_port") == "51322"
    assert parsed.get("raw_dst_port") == "3389"
    assert parsed.get("raw_size") == "0"
    assert parsed.get("raw_direction") == "RECEIVE"
    assert parsed.get("raw_info") == "-"
    # Verify unlisted index 9 is preserved as col_9
    assert parsed.get("col_9") == "S"


def test_cisco_asa_syslog_parser():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Cisco", "Adaptive Security Appliance")
    assert config is not None
    parser = get_parser(config)
    assert isinstance(parser, SyslogParser)

    # Built connection line (302013)
    line1 = "Aug 31 2026 15:45:01: %ASA-6-302013: Built outbound TCP connection 104521 for outside:142.250.190.46/443 (142.250.190.46/443) to inside:192.168.1.105/51220 (203.0.113.10/15220)"
    parsed1 = parser.parse(line1)
    assert parsed1 is not None
    assert parsed1.get("raw_timestamp") == "Aug 31 2026 15:45:01"
    assert parsed1.get("raw_severity") == "6"
    assert parsed1.get("raw_message_id") == "302013"
    assert parsed1.get("message_family") == "connection"
    assert parsed1.get("event_action") == "open"
    assert parsed1.get("raw_protocol") == "TCP"
    assert parsed1.get("raw_connection_id") == "104521"
    assert parsed1.get("raw_src_ip") == "142.250.190.46"
    assert parsed1.get("raw_src_port") == "443"
    assert parsed1.get("raw_dst_ip") == "192.168.1.105"
    assert parsed1.get("raw_dst_port") == "51220"

    # Deny line (106023)
    line2 = 'Aug 31 2026 15:45:12: %ASA-4-106023: Deny tcp src outside:45.227.254.12/58231 dst inside:192.168.1.50/22 by access-group "OUTSIDE_IN" [0x0, 0x0]'
    parsed2 = parser.parse(line2)
    assert parsed2 is not None
    assert parsed2.get("raw_message_id") == "106023"
    assert parsed2.get("message_family") == "access_control"
    assert parsed2.get("event_action") == "deny"
    assert parsed2.get("raw_src_ip") == "45.227.254.12"
    assert parsed2.get("raw_dst_ip") == "192.168.1.50"
    assert parsed2.get("raw_access_group") == "OUTSIDE_IN"


def test_suricata_json_parser():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("OISF", "Suricata")
    assert config is not None
    parser = get_parser(config)
    assert isinstance(parser, JSONParser)

    line = '{"timestamp":"2026-08-31T15:58:10.001234+0000","flow_id":14023948102394,"in_iface":"eth1","event_type":"alert","src_ip":"192.168.1.105","src_port":49221,"dest_ip":"185.220.101.5","dest_port":6667,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2017321,"rev":3,"signature":"ET MALWARE IRC Botnet Command and Control Activity","category":"A Network Trojan was detected","severity":1},"flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":240,"bytes_toclient":180,"start":"2026-08-31T15:58:09.551221+0000"}}'
    parsed = parser.parse(line)
    assert parsed is not None
    assert parsed.get("raw_timestamp") == "2026-08-31T15:58:10.001234+0000"
    assert parsed.get("raw_src_ip") == "192.168.1.105"
    assert parsed.get("raw_src_port") == 49221
    assert parsed.get("raw_dst_ip") == "185.220.101.5"
    assert parsed.get("raw_dst_port") == 6667
    assert parsed.get("raw_protocol") == "TCP"
    assert parsed.get("raw_alert_action") == "allowed"
    assert parsed.get("raw_signature_id") == 2017321
    assert parsed.get("raw_alert_severity") == 1
    assert parsed.get("raw_bytes_to_server") == 240


def test_palo_alto_csv_parser():
    loader = ConfigLoader(MAPPINGS_DIR)
    config = loader.get_by_source("Palo Alto Networks", "PAN-OS")
    assert config is not None
    parser = get_parser(config)
    assert isinstance(parser, DelimitedParser)

    header_line = '"FUTURE_USE","Receive Time","Serial Number","Type","Subtype","Version","Generate Time","Source IP","Destination IP","NAT Source IP","NAT Destination IP","Rule Name","Source User","Destination User","Application","Virtual System","Source Zone","Destination Zone","Inbound Interface","Outbound Interface","Log Action","FUTURE_USE","Session ID","Repeat Count","Source Port","Destination Port","NAT Source Port","NAT Destination Port","Flags","Protocol","Action","Bytes","Bytes Sent","Bytes Received","Packets","Start Time","Elapsed Time","Category","FUTURE_USE","Sequence Number","Action Flags","Source Country","Destination Country","FUTURE_USE","Packets Sent","Packets Received","Session End Reason"'
    # Header row should return None
    assert parser.parse(header_line) is None

    # Parse with header context
    reader = csv.reader(io.StringIO(header_line))
    headers = next(reader)

    data_line = '"","2026/08/31 15:40:12","0123456789","TRAFFIC","end","1","2026/08/31 15:40:12","192.168.1.142","52.113.194.132","203.0.113.10","52.113.194.132","Allow-Office365","acme\\j.doe","","ms-teams","vsys1","Trust","Untrust","ethernet1/2","ethernet1/1","default","","105214","1","61043","443","16043","443","0x400000","tcp","allow","451200","151200","300000","420","2026/08/31 15:35:12","300","business-and-economy","","8453221","0x0","United States","United States","","180","240","tcp-fin"'
    parsed = parser.parse(data_line, header_context=headers)
    assert parsed is not None
    assert parsed.get("raw_src_ip") == "192.168.1.142"
    assert parsed.get("raw_dst_ip") == "52.113.194.132"
    assert parsed.get("raw_action") == "allow"
    assert parsed.get("raw_type") == "TRAFFIC"
    assert parsed.get("raw_bytes") == "451200"


def test_key_value_parser():
    loader = ConfigLoader(MAPPINGS_DIR)
    # Using Windows Firewall config as base for KV test
    config = loader.get_by_source("Microsoft", "Windows Firewall")
    config.raw_config["parsing"]["fields"] = {"src": "raw_src_ip", "dst": "raw_dst_ip"}
    kv_parser = KeyValueParser(config)

    line = 'device="fw01" src=192.168.1.1 dst=10.0.0.1 action="DROP" proto=TCP'
    parsed = kv_parser.parse(line)
    assert parsed is not None
    assert parsed.get("raw_src_ip") == "192.168.1.1"
    assert parsed.get("raw_dst_ip") == "10.0.0.1"
    assert parsed.get("device") == "fw01"
    assert parsed.get("action") == "DROP"
