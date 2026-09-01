export interface VendorYAMLConfig {
  id: string;
  vendor: string;
  product: string;
  format: 'csv' | 'json' | 'kv' | 'syslog' | 'xml';
  description: string;
  yamlContent: string;
  detection: {
    method: 'field_presence' | 'regex' | 'json_schema' | 'header_match';
    required_fields?: string[];
    pattern?: string;
  };
  sampleRaw: string;
}

export const VENDOR_YAML_CONFIGS: VendorYAMLConfig[] = [
  {
    id: 'paloalto-panos',
    vendor: 'Palo Alto Networks',
    product: 'PAN-OS Traffic',
    format: 'csv',
    description: 'Declarative mapping config for Palo Alto Networks Next-Gen Firewall traffic CSV logs',
    sampleRaw: '1,2026/08/27 09:14:02,traffic,TRAFFIC,deny,2818,2026/08/27 09:14:02,203.0.113.45,10.0.4.12,0.0.0.0,0.0.0.0,rule-block-ssh-external,,,ssh,vsys1,untrust,trust,ethernet1/1,ethernet1/2,edge-fw-01,2026/08/27 09:14:02,998812,1,51322,22,0,0,0x0,tcp,deny,68,68,0,1',
    yamlContent: `source_identity:
  vendor: "Palo Alto Networks"
  product: "PAN-OS"
  format: "csv"
  delimiter: ","

detection:
  method: "field_presence"
  csv_index_match:
    index_2: "traffic"
    index_3: "TRAFFIC"

classification:
  target_class: "Network Activity"
  class_uid: 4001

field_map:
  col_7: "src_endpoint.ip"
  col_23: "src_endpoint.port"
  col_8: "dst_endpoint.ip"
  col_24: "dst_endpoint.port"
  col_11: "firewall_rule.name"
  col_28: "connection_info.protocol_name"
  col_19: "device.name"
  col_1: "time"
  col_4: "activity_name"

transforms:
  col_4:
    deny: { activity_id: 6, activity_name: "Deny" }
    allow: { activity_id: 1, activity_name: "Allow" }
    drop: { activity_id: 2, activity_name: "Drop" }
  col_28:
    tcp: "TCP"
    udp: "UDP"
    icmp: "ICMP"

static_fields:
  "device.vendor_name": "Palo Alto Networks"
  "device.type": "Firewall"

unmapped_policy:
  action: "bucket"
  target: "unmapped"
  columns:
    col_14: "app"
    col_15: "vsys"
    col_16: "zone_in"
    col_17: "zone_out"

raw_preservation:
  enabled: true
  target_field: "raw_data"
  generate_uuid: true`,
    detection: {
      method: 'field_presence',
      required_fields: ['traffic', 'TRAFFIC'],
      pattern: '^\\d+,[^,]+,traffic,TRAFFIC,.*'
    }
  },
  {
    id: 'suricata-eve',
    vendor: 'OISF / Suricata',
    product: 'Suricata EVE IDS',
    format: 'json',
    description: 'Declarative mapping config for Suricata EVE JSON alert telemetry and detection findings',
    sampleRaw: '{"timestamp":"2026-08-27T09:17:33.221000+0000","event_type":"alert","src_ip":"185.220.101.4","src_port":443,"dest_ip":"10.0.4.30","dest_port":51944,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","signature_id":2001219,"category":"Attempted Information Leak","severity":2}}',
    yamlContent: `source_identity:
  vendor: "OISF"
  product: "Suricata"
  format: "json"

detection:
  method: "field_presence"
  required_fields: ["event_type", "alert.signature", "proto"]

classification:
  rule:
    when: "event_type == 'alert'"
    target_class: "Detection Finding"
    class_uid: 2004
  default_class: "Network Activity"

field_map:
  timestamp: "time"
  src_ip: "src_endpoint.ip"
  src_port: "src_endpoint.port"
  dest_ip: "dst_endpoint.ip"
  dest_port: "dst_endpoint.port"
  proto: "connection_info.protocol_name"
  alert.signature_id: "finding_info.uid"
  alert.signature: "finding_info.title"
  alert.category: "finding_info.desc"
  alert.severity: "severity"

transforms:
  alert.severity:
    1: { severity: "Critical", severity_id: 5 }
    2: { severity: "High", severity_id: 4 }
    3: { severity: "Medium", severity_id: 3 }
    4: { severity: "Low", severity_id: 2 }

static_fields:
  "activity_name": "Create"
  "activity_id": 1
  "device.vendor_name": "OISF"
  "device.type": "IDS/IPS"
  "device.name": "Suricata"

unmapped_policy:
  action: "bucket"
  target: "unmapped"

raw_preservation:
  enabled: true
  target_field: "raw_data"
  generate_uuid: true`,
    detection: {
      method: 'json_schema',
      required_fields: ['event_type', 'alert']
    }
  },
  {
    id: 'fortinet-fortios',
    vendor: 'Fortinet',
    product: 'FortiOS',
    format: 'kv',
    description: 'Declarative mapping config for Fortinet FortiGate UTM / Firewall key-value syslog streams',
    sampleRaw: 'devname="FG-HQ-FW01" devid="FGT60D4614041234" date=2026-08-27 time=09:18:44 logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.105 srcport=54211 srcintf="port2" dstip=172.217.16.206 dstport=443 dstintf="wan1" polid=4 policyname="allow-outbound-web" action="accept" proto=6 duration=42 sentbyte=1250 rcvdbyte=8900 app="HTTPS"',
    yamlContent: `source_identity:
  vendor: "Fortinet"
  product: "FortiOS"
  format: "kv"

detection:
  method: "field_presence"
  required_fields: ["devname", "logid", "policyname"]

classification:
  target_class: "Network Activity"
  class_uid: 4001

field_map:
  srcip: "src_endpoint.ip"
  srcport: "src_endpoint.port"
  dstip: "dst_endpoint.ip"
  dstport: "dst_endpoint.port"
  srcintf: "src_endpoint.interface"
  dstintf: "dst_endpoint.interface"
  policyname: "firewall_rule.name"
  devname: "device.name"
  action: "activity_name"
  sentbyte: "src_endpoint.bytes"
  rcvdbyte: "dst_endpoint.bytes"

transforms:
  action:
    accept: { activity_id: 1, activity_name: "Allow" }
    deny: { activity_id: 6, activity_name: "Deny" }
    close: { activity_id: 3, activity_name: "Close" }
  proto:
    6: "TCP"
    17: "UDP"
    1: "ICMP"

static_fields:
  "device.vendor_name": "Fortinet"
  "device.type": "Firewall"

unmapped_policy:
  action: "bucket"
  target: "unmapped"
  exclude_from_unmapped: ["date", "time"]

raw_preservation:
  enabled: true
  target_field: "raw_data"
  generate_uuid: true`,
    detection: {
      method: 'field_presence',
      required_fields: ['devname', 'logid', 'policyname']
    }
  },
  {
    id: 'cisco-asa',
    vendor: 'Cisco',
    product: 'Cisco ASA',
    format: 'syslog',
    description: 'Declarative mapping config for Cisco Adaptive Security Appliance (ASA) syslog messages',
    sampleRaw: '%ASA-4-106023: Deny tcp src outside:198.51.100.77/49152 dst inside:10.0.4.15/3389 by access-group "perimeter-inbound" [0x41235a, 0x0]',
    yamlContent: `source_identity:
  vendor: "Cisco"
  product: "Cisco ASA"
  format: "syslog"

detection:
  method: "regex"
  pattern: "%ASA-[1-7]-[0-9]{6}:"

classification:
  target_class: "Network Activity"
  class_uid: 4001

regex_capture:
  pattern: "%ASA-(?<severity_code>[1-7])-(?<msg_id>[0-9]+):\\s+(?<action>Deny|Built|Teardown)\\s+(?<proto>\\w+)\\s+src\\s+(?<src_zone>\\w+):(?<src_ip>[0-9.]+)/(?<src_port>\\d+)\\s+dst\\s+(?<dst_zone>\\w+):(?<dst_ip>[0-9.]+)/(?<dst_port>\\d+)\\s+by\\s+access-group\\s+\"(?<acl_name>[^\"]+)\""

field_map:
  src_ip: "src_endpoint.ip"
  src_port: "src_endpoint.port"
  src_zone: "src_endpoint.zone"
  dst_ip: "dst_endpoint.ip"
  dst_port: "dst_endpoint.port"
  dst_zone: "dst_endpoint.zone"
  proto: "connection_info.protocol_name"
  acl_name: "firewall_rule.name"
  action: "activity_name"

transforms:
  action:
    Deny: { activity_id: 6, activity_name: "Deny" }
    Built: { activity_id: 1, activity_name: "Allow" }
    Teardown: { activity_id: 3, activity_name: "Close" }
  proto:
    tcp: "TCP"
    udp: "UDP"
    icmp: "ICMP"

static_fields:
  "device.vendor_name": "Cisco"
  "device.type": "Firewall"
  "device.name": "cisco-asa-edge"

unmapped_policy:
  action: "bucket"
  target: "unmapped"

raw_preservation:
  enabled: true
  target_field: "raw_data"
  generate_uuid: true`,
    detection: {
      method: 'regex',
      pattern: '%ASA-\\d-\\d{6}'
    }
  }
];
