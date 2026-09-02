import { PresetSampleLog } from '../types/assistant';

export const PRESET_UNKNOWN_SAMPLES: PresetSampleLog[] = [
  {
    id: 'sonicwall_kv',
    name: 'SonicWall NSa Firewall',
    vendor: 'SonicWall',
    deviceType: 'firewall',
    format: 'key_value',
    description: 'Key-value syslog from SonicWall perimeter gateway containing IP/port bindings and rule actions.',
    rawLines: [
      'time="2026-08-27 09:14:02" fw_id="NSa-3700" action="deny" proto="TCP" srcip=203.0.113.45 dstip=10.0.4.12 sport=51322 dport=22 msg="Inbound SSH blocked by policy"',
      'time="2026-08-27 09:14:05" fw_id="NSa-3700" action="allow" proto="TCP" srcip=192.168.1.10 dstip=10.0.4.12 sport=43211 dport=443 msg="HTTPS egress traffic"',
      'time="2026-08-27 09:14:10" fw_id="NSa-3700" action="deny" proto="UDP" srcip=198.51.100.77 dstip=10.0.4.53 sport=62100 dport=53 msg="DNS Amplification attempt blocked"'
    ]
  },
  {
    id: 'checkpoint_syslog',
    name: 'CheckPoint Quantum Gateway',
    vendor: 'CheckPoint',
    deviceType: 'firewall',
    format: 'syslog',
    description: 'Standard RFC3164 syslog header with CheckPoint security action tags and protocol info.',
    rawLines: [
      '<134>Aug 27 09:15:33 cp-edge-01 SmartDefense: action="drop" proto=6 src=45.33.32.156 dst=10.0.0.14 s_port=58912 service=3389 rule_name="Block_RDP_External"',
      '<134>Aug 27 09:15:36 cp-edge-01 SmartDefense: action="accept" proto=6 src=10.0.1.50 dst=172.16.0.5 s_port=50123 service=80 rule_name="Allow_Web_Internal"'
    ]
  },
  {
    id: 'space_delimited_router',
    name: 'Edge Router Traffic Log',
    vendor: 'Custom Edge',
    deviceType: 'router',
    format: 'space_delimited',
    description: 'Space-delimited raw log stream from an unknown perimeter router.',
    rawLines: [
      '2026-08-27 09:20:11 DROP TCP 198.51.100.99 10.0.2.15 44321 80 0 S 1420 0 4096 RECEIVE',
      '2026-08-27 09:20:14 ALLOW TCP 10.0.2.100 172.217.14.206 52104 443 0 S 2048 0 8192 SEND'
    ]
  },
  {
    id: 'json_waf_alert',
    name: 'Cloudflare WAF Finding',
    vendor: 'Cloudflare',
    deviceType: 'proxy',
    format: 'json',
    description: 'Nested JSON web application firewall event payload with threat details.',
    rawLines: [
      '{"timestamp":"2026-08-27T09:22:01Z","client_ip":"198.51.100.220","server_ip":"10.0.4.80","client_port":54321,"server_port":80,"protocol":"TCP","action":"block","rule_id":"WAF-100293","threat_category":"SQL_Injection","user_agent":"sqlmap/1.5"}',
      '{"timestamp":"2026-08-27T09:22:05Z","client_ip":"203.0.113.88","server_ip":"10.0.4.80","client_port":54322,"server_port":443,"protocol":"TCP","action":"allow","rule_id":"DEFAULT_ALLOW","threat_category":"none","user_agent":"Mozilla/5.0"}'
    ]
  }
];
