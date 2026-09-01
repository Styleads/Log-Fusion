/**
 * Open Cybersecurity Schema Framework (OCSF) v1.1.0 Type Definitions
 * Specifically tailored for Perimeter Network Device Logs (Firewalls, IDS/IPS, WAF, Routers)
 */

export type OCSFClassName = 'Network Activity' | 'Detection Finding' | 'Security Finding' | 'DNS Activity';
export type OCSFClassUID = 4001 | 2004 | 2001 | 4003;

export interface OCSFEndpoint {
  ip: string;
  port?: number;
  hostname?: string;
  mac?: string;
  packets?: number;
  bytes?: number;
  interface?: string;
  zone?: string;
}

export interface OCSFConnectionInfo {
  protocol_name?: string;
  protocol_num?: number;
  direction?: string;
  tcp_flags?: string | number;
  session_id?: string | number;
}

export interface OCSFFirewallRule {
  name: string;
  uid?: string;
  type?: string;
}

export interface OCSFFindingInfo {
  uid: string;
  title: string;
  desc?: string;
  category?: string;
  severity?: string;
  confidence?: string;
  types?: string[];
  analytic?: {
    name?: string;
    type?: string;
  };
}

export interface OCSFDevice {
  name: string;
  vendor_name: string;
  type: string;
  model?: string;
  version?: string;
  ip?: string;
}

export interface OCSFEvent {
  // Core OCSF metadata
  class_name: OCSFClassName;
  class_uid: OCSFClassUID;
  activity_name: string;
  activity_id: number;
  category_name?: string;
  category_uid?: number;
  severity?: string;
  severity_id?: number;
  time: string; // ISO 8601 UTC
  
  // Traceability & Lineage
  event_uid: string; // Shared UUID connecting normalized event to raw form
  raw_data: string; // Pristine raw event string
  raw_format: 'csv' | 'json' | 'kv' | 'syslog' | 'xml';
  source_vendor: string;
  source_product: string;
  
  // Branched OCSF Entities
  src_endpoint?: OCSFEndpoint;
  dst_endpoint?: OCSFEndpoint;
  connection_info?: OCSFConnectionInfo;
  firewall_rule?: OCSFFirewallRule;
  finding_info?: OCSFFindingInfo;
  device: OCSFDevice;
  
  // Unmapped / Preservation Bucket (Guarantees zero data loss)
  unmapped?: Record<string, any>;
  
  // Pipeline processing telemetry
  processing_metadata?: {
    ingest_time: string;
    matched_config: string;
    parser_time_ms: number;
    normalization_status: 'complete' | 'partial' | 'fallback';
  };
}

export interface FieldMappingLineage {
  raw_field: string;
  raw_value: string | number | boolean | null;
  ocsf_path: string;
  transformation?: string;
  status: 'mapped' | 'unmapped' | 'static' | 'transformed';
}
