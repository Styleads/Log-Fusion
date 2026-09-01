import { OCSFEvent } from '../types/ocsf';

export const INITIAL_MOCK_EVENTS: OCSFEvent[] = [
  // 1. Palo Alto - SSH Deny (From Solution Document Section 3, Example A)
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Deny',
    activity_id: 6,
    time: '2026-08-27T09:14:02Z',
    event_uid: 'e4b2d184-7a39-4911-9f25-394bf3421001',
    source_vendor: 'Palo Alto Networks',
    source_product: 'PAN-OS',
    raw_format: 'csv',
    raw_data: '1,2026/08/27 09:14:02,traffic,TRAFFIC,deny,2818,2026/08/27 09:14:02,203.0.113.45,10.0.4.12,0.0.0.0,0.0.0.0,rule-block-ssh-external,,,ssh,vsys1,untrust,trust,ethernet1/1,ethernet1/2,edge-fw-01,2026/08/27 09:14:02,998812,1,51322,22,0,0,0x0,tcp,deny,68,68,0,1',
    src_endpoint: {
      ip: '203.0.113.45',
      port: 51322,
      zone: 'untrust',
      interface: 'ethernet1/1',
      bytes: 68,
      packets: 1
    },
    dst_endpoint: {
      ip: '10.0.4.12',
      port: 22,
      zone: 'trust',
      interface: 'ethernet1/2',
      bytes: 0,
      packets: 0
    },
    connection_info: {
      protocol_name: 'TCP',
      direction: 'inbound',
      session_id: 998812
    },
    firewall_rule: {
      name: 'rule-block-ssh-external',
      uid: '2818',
      type: 'Security Rule'
    },
    device: {
      name: 'edge-fw-01',
      vendor_name: 'Palo Alto Networks',
      type: 'Firewall',
      model: 'PA-5220'
    },
    unmapped: {
      vsys: 'vsys1',
      zone_in: 'untrust',
      zone_out: 'trust',
      nat_src_ip: '0.0.0.0',
      nat_dst_ip: '0.0.0.0',
      app: 'ssh'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:14:02.045Z',
      matched_config: 'paloalto-panos.yaml',
      parser_time_ms: 1.2,
      normalization_status: 'complete'
    }
  },

  // 2. Suricata IDS Alert (From Solution Document Section 3, Example B)
  {
    class_name: 'Detection Finding',
    class_uid: 2004,
    activity_name: 'Create',
    activity_id: 1,
    severity: 'High',
    severity_id: 4,
    time: '2026-08-27T09:17:33.221Z',
    event_uid: 'b819f72e-3329-450b-8df5-a764dca39221',
    source_vendor: 'OISF / Suricata',
    source_product: 'Suricata EVE',
    raw_format: 'json',
    raw_data: '{"timestamp":"2026-08-27T09:17:33.221000+0000","event_type":"alert","src_ip":"185.220.101.4","src_port":443,"dest_ip":"10.0.4.30","dest_port":51944,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","signature_id":2001219,"category":"Attempted Information Leak","severity":2}}',
    finding_info: {
      uid: '2001219',
      title: 'ET SCAN Potential SSH Scan',
      desc: 'Attempted Information Leak',
      category: 'Scan / Reconnaissance',
      severity: 'High',
      confidence: 'High'
    },
    src_endpoint: {
      ip: '185.220.101.4',
      port: 443
    },
    dst_endpoint: {
      ip: '10.0.4.30',
      port: 51944
    },
    connection_info: {
      protocol_name: 'TCP'
    },
    device: {
      name: 'suricata-sensor-01',
      vendor_name: 'OISF',
      type: 'IDS/IPS'
    },
    unmapped: {
      eve_version: 1,
      flow_id: 1892837192,
      in_iface: 'eth0'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:17:33.235Z',
      matched_config: 'suricata-eve.yaml',
      parser_time_ms: 0.8,
      normalization_status: 'complete'
    }
  },

  // 3. Fortinet FortiOS Traffic Allowed
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Allow',
    activity_id: 1,
    time: '2026-08-27T09:18:44Z',
    event_uid: 'fa720e11-85bc-42b1-912a-61c028a30144',
    source_vendor: 'Fortinet',
    source_product: 'FortiOS',
    raw_format: 'kv',
    raw_data: 'devname="FG-HQ-FW01" devid="FGT60D4614041234" date=2026-08-27 time=09:18:44 logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.105 srcport=54211 srcintf="port2" dstip=172.217.16.206 dstport=443 dstintf="wan1" polid=4 policyname="allow-outbound-web" action="accept" proto=6 duration=42 sentbyte=1250 rcvdbyte=8900 app="HTTPS"',
    src_endpoint: {
      ip: '192.168.1.105',
      port: 54211,
      interface: 'port2',
      bytes: 1250
    },
    dst_endpoint: {
      ip: '172.217.16.206',
      port: 443,
      interface: 'wan1',
      bytes: 8900
    },
    connection_info: {
      protocol_name: 'TCP',
      protocol_num: 6,
      direction: 'outbound'
    },
    firewall_rule: {
      name: 'allow-outbound-web',
      uid: '4'
    },
    device: {
      name: 'FG-HQ-FW01',
      vendor_name: 'Fortinet',
      type: 'Firewall',
      model: 'FortiGate-60D'
    },
    unmapped: {
      devid: 'FGT60D4614041234',
      subtype: 'forward',
      level: 'notice',
      duration: 42,
      app: 'HTTPS'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:18:44.112Z',
      matched_config: 'fortinet-fortios.yaml',
      parser_time_ms: 1.5,
      normalization_status: 'complete'
    }
  },

  // 4. Cisco ASA Syslog Deny (RDP port 3389)
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Deny',
    activity_id: 6,
    time: '2026-08-27T09:19:12Z',
    event_uid: '38a19f20-410a-4c22-b5e1-8890ac301912',
    source_vendor: 'Cisco',
    source_product: 'Cisco ASA',
    raw_format: 'syslog',
    raw_data: '%ASA-4-106023: Deny tcp src outside:198.51.100.77/49152 dst inside:10.0.4.15/3389 by access-group "perimeter-inbound" [0x41235a, 0x0]',
    src_endpoint: {
      ip: '198.51.100.77',
      port: 49152,
      zone: 'outside'
    },
    dst_endpoint: {
      ip: '10.0.4.15',
      port: 3389,
      zone: 'inside'
    },
    connection_info: {
      protocol_name: 'TCP'
    },
    firewall_rule: {
      name: 'perimeter-inbound'
    },
    device: {
      name: 'cisco-asa-edge',
      vendor_name: 'Cisco',
      type: 'Firewall'
    },
    unmapped: {
      msg_id: '106023',
      severity_code: '4',
      hex_signature: ['0x41235a', '0x0']
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:19:12.080Z',
      matched_config: 'cisco-asa.yaml',
      parser_time_ms: 1.1,
      normalization_status: 'complete'
    }
  },

  // 5. Suricata IDS Alert - SQL Injection Attack
  {
    class_name: 'Detection Finding',
    class_uid: 2004,
    activity_name: 'Create',
    activity_id: 1,
    severity: 'Critical',
    severity_id: 5,
    time: '2026-08-27T09:21:05Z',
    event_uid: '77f10b24-912b-4228-98e9-55018b100921',
    source_vendor: 'OISF / Suricata',
    source_product: 'Suricata EVE',
    raw_format: 'json',
    raw_data: '{"timestamp":"2026-08-27T09:21:05.118000+0000","event_type":"alert","src_ip":"45.33.32.156","src_port":39822,"dest_ip":"10.0.4.80","dest_port":80,"proto":"TCP","alert":{"signature":"ET WEB_SERVER Possible SQL Injection Attempt (UNION SELECT)","signature_id":2014819,"category":"Web Application Attack","severity":1}}',
    finding_info: {
      uid: '2014819',
      title: 'ET WEB_SERVER Possible SQL Injection Attempt (UNION SELECT)',
      desc: 'Web Application Attack',
      category: 'Exploit Attempt',
      severity: 'Critical',
      confidence: 'High'
    },
    src_endpoint: {
      ip: '45.33.32.156',
      port: 39822
    },
    dst_endpoint: {
      ip: '10.0.4.80',
      port: 80
    },
    connection_info: {
      protocol_name: 'TCP'
    },
    device: {
      name: 'suricata-sensor-01',
      vendor_name: 'OISF',
      type: 'IDS/IPS'
    },
    unmapped: {
      payload_matched: "UNION SELECT NULL, username, password FROM users",
      http_uri: "/api/v1/search?q=1%20UNION%20SELECT%20NULL"
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:21:05.130Z',
      matched_config: 'suricata-eve.yaml',
      parser_time_ms: 0.9,
      normalization_status: 'complete'
    }
  },

  // 6. Fortinet - SMB Exploit Deny (Port 445)
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Deny',
    activity_id: 6,
    time: '2026-08-27T09:22:15Z',
    event_uid: 'a8910245-6671-46ab-bb10-911874630215',
    source_vendor: 'Fortinet',
    source_product: 'FortiOS',
    raw_format: 'kv',
    raw_data: 'devname="FG-HQ-FW01" devid="FGT60D4614041234" date=2026-08-27 time=09:22:15 logid="0000000014" type="traffic" subtype="forward" level="warning" srcip=91.240.118.172 srcport=43820 srcintf="wan1" dstip=192.168.1.50 dstport=445 dstintf="port2" polid=0 policyname="default-deny-inbound" action="deny" proto=6 duration=0 sentbyte=0 rcvdbyte=0 app="SMB"',
    src_endpoint: {
      ip: '91.240.118.172',
      port: 43820,
      interface: 'wan1',
      bytes: 0
    },
    dst_endpoint: {
      ip: '192.168.1.50',
      port: 445,
      interface: 'port2',
      bytes: 0
    },
    connection_info: {
      protocol_name: 'TCP',
      protocol_num: 6
    },
    firewall_rule: {
      name: 'default-deny-inbound',
      uid: '0'
    },
    device: {
      name: 'FG-HQ-FW01',
      vendor_name: 'Fortinet',
      type: 'Firewall',
      model: 'FortiGate-60D'
    },
    unmapped: {
      level: 'warning',
      app: 'SMB',
      polid: 0
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:22:15.050Z',
      matched_config: 'fortinet-fortios.yaml',
      parser_time_ms: 1.4,
      normalization_status: 'complete'
    }
  },

  // 7. Palo Alto - Outbound HTTPS Allow
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Allow',
    activity_id: 1,
    time: '2026-08-27T09:23:40Z',
    event_uid: '12ba834f-0982-4aa1-9755-408992019234',
    source_vendor: 'Palo Alto Networks',
    source_product: 'PAN-OS',
    raw_format: 'csv',
    raw_data: '1,2026/08/27 09:23:40,traffic,TRAFFIC,allow,2819,2026/08/27 09:23:40,10.0.4.50,142.250.190.46,0.0.0.0,0.0.0.0,rule-allow-outbound-web,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,edge-fw-01,2026/08/27 09:23:40,998813,1,49821,443,0,0,0x0,tcp,allow,1420,8450,0,1',
    src_endpoint: {
      ip: '10.0.4.50',
      port: 49821,
      zone: 'trust',
      interface: 'ethernet1/2',
      bytes: 1420,
      packets: 12
    },
    dst_endpoint: {
      ip: '142.250.190.46',
      port: 443,
      zone: 'untrust',
      interface: 'ethernet1/1',
      bytes: 8450,
      packets: 18
    },
    connection_info: {
      protocol_name: 'TCP',
      direction: 'outbound',
      session_id: 998813
    },
    firewall_rule: {
      name: 'rule-allow-outbound-web',
      uid: '2819'
    },
    device: {
      name: 'edge-fw-01',
      vendor_name: 'Palo Alto Networks',
      type: 'Firewall',
      model: 'PA-5220'
    },
    unmapped: {
      app: 'ssl',
      vsys: 'vsys1'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:23:40.090Z',
      matched_config: 'paloalto-panos.yaml',
      parser_time_ms: 1.1,
      normalization_status: 'complete'
    }
  },

  // 8. Palo Alto - Repeated SSH Deny (Same attacker 203.0.113.45)
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Deny',
    activity_id: 6,
    time: '2026-08-27T09:24:05Z',
    event_uid: 'f87a3290-bc42-49aa-912f-682944010924',
    source_vendor: 'Palo Alto Networks',
    source_product: 'PAN-OS',
    raw_format: 'csv',
    raw_data: '1,2026/08/27 09:24:05,traffic,TRAFFIC,deny,2818,2026/08/27 09:24:05,203.0.113.45,10.0.4.12,0.0.0.0,0.0.0.0,rule-block-ssh-external,,,ssh,vsys1,untrust,trust,ethernet1/1,ethernet1/2,edge-fw-01,2026/08/27 09:24:05,998814,1,51328,22,0,0,0x0,tcp,deny,68,68,0,1',
    src_endpoint: {
      ip: '203.0.113.45',
      port: 51328,
      zone: 'untrust',
      bytes: 68
    },
    dst_endpoint: {
      ip: '10.0.4.12',
      port: 22,
      zone: 'trust',
      bytes: 0
    },
    connection_info: {
      protocol_name: 'TCP'
    },
    firewall_rule: {
      name: 'rule-block-ssh-external',
      uid: '2818'
    },
    device: {
      name: 'edge-fw-01',
      vendor_name: 'Palo Alto Networks',
      type: 'Firewall'
    },
    unmapped: {
      zone_in: 'untrust',
      zone_out: 'trust',
      app: 'ssh'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:24:05.020Z',
      matched_config: 'paloalto-panos.yaml',
      parser_time_ms: 1.0,
      normalization_status: 'complete'
    }
  },

  // 9. Suricata - Repeated SSH Scan Finding
  {
    class_name: 'Detection Finding',
    class_uid: 2004,
    activity_name: 'Create',
    activity_id: 1,
    severity: 'High',
    severity_id: 4,
    time: '2026-08-27T09:25:18Z',
    event_uid: '49aa2145-09df-419b-a012-683920192518',
    source_vendor: 'OISF / Suricata',
    source_product: 'Suricata EVE',
    raw_format: 'json',
    raw_data: '{"timestamp":"2026-08-27T09:25:18.450000+0000","event_type":"alert","src_ip":"185.220.101.4","src_port":443,"dest_ip":"10.0.4.35","dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","signature_id":2001219,"category":"Attempted Information Leak","severity":2}}',
    finding_info: {
      uid: '2001219',
      title: 'ET SCAN Potential SSH Scan',
      desc: 'Attempted Information Leak',
      category: 'Scan / Reconnaissance',
      severity: 'High'
    },
    src_endpoint: {
      ip: '185.220.101.4',
      port: 443
    },
    dst_endpoint: {
      ip: '10.0.4.35',
      port: 22
    },
    connection_info: {
      protocol_name: 'TCP'
    },
    device: {
      name: 'suricata-sensor-01',
      vendor_name: 'OISF',
      type: 'IDS/IPS'
    },
    unmapped: {
      target_host: 'dmz-bastion-02'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:25:18.460Z',
      matched_config: 'suricata-eve.yaml',
      parser_time_ms: 0.9,
      normalization_status: 'complete'
    }
  },

  // 10. Cisco ASA - DNS Query Allow (UDP 53)
  {
    class_name: 'Network Activity',
    class_uid: 4001,
    activity_name: 'Allow',
    activity_id: 1,
    time: '2026-08-27T09:26:01Z',
    event_uid: '99bf3812-701a-4638-b42a-718293019260',
    source_vendor: 'Cisco',
    source_product: 'Cisco ASA',
    raw_format: 'syslog',
    raw_data: '%ASA-4-106023: Built udp src inside:10.0.4.50/53120 dst outside:8.8.8.8/53 by access-group "perimeter-outbound" [0x41235b, 0x0]',
    src_endpoint: {
      ip: '10.0.4.50',
      port: 53120,
      zone: 'inside'
    },
    dst_endpoint: {
      ip: '8.8.8.8',
      port: 53,
      zone: 'outside'
    },
    connection_info: {
      protocol_name: 'UDP'
    },
    firewall_rule: {
      name: 'perimeter-outbound'
    },
    device: {
      name: 'cisco-asa-edge',
      vendor_name: 'Cisco',
      type: 'Firewall'
    },
    unmapped: {
      msg_id: '106023'
    },
    processing_metadata: {
      ingest_time: '2026-08-27T09:26:01.030Z',
      matched_config: 'cisco-asa.yaml',
      parser_time_ms: 1.0,
      normalization_status: 'complete'
    }
  }
];
