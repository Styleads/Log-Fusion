export interface SampleLogItem {
  id: string;
  vendor: string;
  category: string;
  name: string;
  format: 'csv' | 'json' | 'kv' | 'syslog';
  raw: string;
  expectedClass: string;
  description: string;
}

export const SAMPLE_RAW_LOGS: SampleLogItem[] = [
  {
    id: 'sample-paloalto-1',
    vendor: 'Palo Alto Networks',
    category: 'Firewall Deny',
    name: 'Palo Alto - SSH Brute Force Deny',
    format: 'csv',
    raw: '1,2026/08/27 09:14:02,traffic,TRAFFIC,deny,2818,2026/08/27 09:14:02,203.0.113.45,10.0.4.12,0.0.0.0,0.0.0.0,rule-block-ssh-external,,,ssh,vsys1,untrust,trust,ethernet1/1,ethernet1/2,edge-fw-01,2026/08/27 09:14:02,998812,1,51322,22,0,0,0x0,tcp,deny,68,68,0,1',
    expectedClass: 'Network Activity (4001)',
    description: 'External SSH connection attempt blocked at the perimeter edge firewall'
  },
  {
    id: 'sample-paloalto-2',
    vendor: 'Palo Alto Networks',
    category: 'Firewall Allow',
    name: 'Palo Alto - Outbound HTTPS Traffic',
    format: 'csv',
    raw: '1,2026/08/27 09:15:10,traffic,TRAFFIC,allow,2819,2026/08/27 09:15:10,10.0.4.50,142.250.190.46,0.0.0.0,0.0.0.0,rule-allow-outbound-web,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,edge-fw-01,2026/08/27 09:15:10,998813,1,49821,443,0,0,0x0,tcp,allow,1420,8450,0,1',
    expectedClass: 'Network Activity (4001)',
    description: 'Internal client reaching Google public services over TLS 443'
  },
  {
    id: 'sample-suricata-1',
    vendor: 'Suricata IDS',
    category: 'IDS Detection Alert',
    name: 'Suricata - Potential SSH Scan Alert',
    format: 'json',
    raw: '{"timestamp":"2026-08-27T09:17:33.221000+0000","event_type":"alert","src_ip":"185.220.101.4","src_port":443,"dest_ip":"10.0.4.30","dest_port":51944,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","signature_id":2001219,"category":"Attempted Information Leak","severity":2}}',
    expectedClass: 'Detection Finding (2004)',
    description: 'High-severity detection finding from Emerging Threats signature rule'
  },
  {
    id: 'sample-suricata-2',
    vendor: 'Suricata IDS',
    category: 'IDS Detection Alert',
    name: 'Suricata - SQL Injection Attempt in URI',
    format: 'json',
    raw: '{"timestamp":"2026-08-27T09:21:05.118000+0000","event_type":"alert","src_ip":"45.33.32.156","src_port":39822,"dest_ip":"10.0.4.80","dest_port":80,"proto":"TCP","alert":{"signature":"ET WEB_SERVER Possible SQL Injection Attempt (UNION SELECT)","signature_id":2014819,"category":"Web Application Attack","severity":1}}',
    expectedClass: 'Detection Finding (2004)',
    description: 'Critical detection finding targeting internal web DMZ service'
  },
  {
    id: 'sample-fortinet-1',
    vendor: 'Fortinet',
    category: 'UTM / Firewall',
    name: 'FortiOS - Allowed Forward Traffic',
    format: 'kv',
    raw: 'devname="FG-HQ-FW01" devid="FGT60D4614041234" date=2026-08-27 time=09:18:44 logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.105 srcport=54211 srcintf="port2" dstip=172.217.16.206 dstport=443 dstintf="wan1" polid=4 policyname="allow-outbound-web" action="accept" proto=6 duration=42 sentbyte=1250 rcvdbyte=8900 app="HTTPS"',
    expectedClass: 'Network Activity (4001)',
    description: 'Enterprise workstation outbound secure session via FortiGate UTM'
  },
  {
    id: 'sample-fortinet-2',
    vendor: 'Fortinet',
    category: 'UTM / Firewall Deny',
    name: 'FortiOS - Blocked Inbound Port 445 (SMB)',
    format: 'kv',
    raw: 'devname="FG-HQ-FW01" devid="FGT60D4614041234" date=2026-08-27 time=09:22:15 logid="0000000014" type="traffic" subtype="forward" level="warning" srcip=91.240.118.172 srcport=43820 srcintf="wan1" dstip=192.168.1.50 dstport=445 dstintf="port2" polid=0 policyname="default-deny-inbound" action="deny" proto=6 duration=0 sentbyte=0 rcvdbyte=0 app="SMB"',
    expectedClass: 'Network Activity (4001)',
    description: 'Inbound SMB exploit attempt blocked by default perimeter rule'
  },
  {
    id: 'sample-cisco-1',
    vendor: 'Cisco',
    category: 'Perimeter Syslog',
    name: 'Cisco ASA - RDP Inbound Deny',
    format: 'syslog',
    raw: '%ASA-4-106023: Deny tcp src outside:198.51.100.77/49152 dst inside:10.0.4.15/3389 by access-group "perimeter-inbound" [0x41235a, 0x0]',
    expectedClass: 'Network Activity (4001)',
    description: 'Access-list block of incoming Remote Desktop Protocol request'
  }
];
