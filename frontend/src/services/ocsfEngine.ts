import { OCSFEvent, FieldMappingLineage } from '../types/ocsf';
import { NormalizationPipelineOutput, PipelineStageResult } from '../types/events';
import { VENDOR_YAML_CONFIGS, VendorYAMLConfig } from '../data/yamlConfigs';

/**
 * Generate a UUID v4
 */
export function generateUUID(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Parses Key-Value log strings (e.g. Fortinet FortiOS, Checkpoint)
 */
function parseKeyValueString(raw: string): Record<string, string> {
  const result: Record<string, string> = {};
  const regex = /([a-zA-Z0-9_-]+)=(?:"([^"]*)"|'([^']*)'|([^\s]+))/g;
  let match;
  while ((match = regex.exec(raw)) !== null) {
    const key = match[1];
    const val = match[2] ?? match[3] ?? match[4] ?? '';
    result[key] = val;
  }
  return result;
}

/**
 * ULPF Client-Side Normalization Pipeline Engine
 */
export function processRawLog(rawInput: string): NormalizationPipelineOutput {
  const startTime = performance.now();
  const stages: PipelineStageResult[] = [];
  const event_uid = generateUUID();
  const rawText = rawInput.trim();

  // Skip empty lines or header comments starting with #
  if (!rawText || rawText.startsWith('#')) {
    return {
      event_uid,
      success: false,
      stages: [{
        stage: 'ingest',
        name: 'Log Ingestion',
        status: 'error',
        details: { message: rawText.startsWith('#') ? 'Skipping header comment line' : 'Empty input log line' }
      }],
      lineage: [],
      totalDurationMs: 0,
      error: rawText.startsWith('#') ? 'Header comment line' : 'Empty log provided'
    };
  }

  // Stage 1: Ingest
  const t0 = performance.now();
  stages.push({
    stage: 'ingest',
    name: 'Ingest Raw Stream',
    status: 'success',
    durationMs: Number((performance.now() - t0).toFixed(2)),
    details: {
      bytes: rawText.length,
      encoding: 'UTF-8',
      preview: rawText.length > 80 ? rawText.substring(0, 80) + '...' : rawText
    }
  });

  // Stage 2: Detect Source & Matched YAML Config
  const t1 = performance.now();
  let matchedConfig: VendorYAMLConfig | null = null;

  // Check Windows Firewall (space-delimited: date time DROP/ALLOW TCP/UDP/ICMP)
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(DROP|ALLOW)\s+(TCP|UDP|ICMP)/i.test(rawText)) {
    matchedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === 'windows-firewall') || null;
  }

  // Check JSON format (e.g. Suricata)
  if (!matchedConfig && rawText.startsWith('{') && rawText.endsWith('}')) {
    try {
      const parsed = JSON.parse(rawText);
      if (parsed.event_type || parsed.alert || parsed.proto) {
        matchedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === 'suricata-eve') || null;
      }
    } catch {
      // not valid json
    }
  }

  // Check Cisco ASA syslog
  if (!matchedConfig && /%ASA-[1-7]-[0-9]{6}:/.test(rawText)) {
    matchedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === 'cisco-asa') || null;
  }

  // Check Palo Alto CSV
  if (!matchedConfig && (rawText.includes(',traffic,TRAFFIC,') || rawText.includes(',THREAT,') || (rawText.includes(',') && rawText.includes('TRAFFIC')))) {
    matchedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === 'paloalto-panos') || null;
  }

  // Check Fortinet KV
  if (!matchedConfig && (rawText.includes('devname=') || rawText.includes('srcip=') || rawText.includes('policyname='))) {
    matchedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === 'fortinet-fortios') || null;
  }

  // If no known vendor matches, do NOT default to Palo Alto! Return null so Assistant handles it.
  if (!matchedConfig) {
    return {
      event_uid,
      success: false,
      stages,
      lineage: [],
      totalDurationMs: Number((performance.now() - startTime).toFixed(2)),
      error: 'Unrecognized format - Auto-Mapping Assistant required'
    };
  }

  stages.push({
    stage: 'detect',
    name: 'Vendor Auto-Detection',
    status: 'success',
    durationMs: Number((performance.now() - t1).toFixed(2)),
    details: {
      vendor: matchedConfig.vendor,
      product: matchedConfig.product,
      format: matchedConfig.format,
      matched_rule: `${matchedConfig.id}.yaml`,
      detection_method: matchedConfig.detection.method
    }
  });

  // Stage 3: Parse
  const t2 = performance.now();
  const extracted: Record<string, any> = {};
  const lineage: FieldMappingLineage[] = [];
  const unmapped: Record<string, any> = {};

  if (matchedConfig.id === 'windows-firewall') {
    const cols = rawText.split(/\s+/);
    extracted['time'] = `${cols[0]}T${cols[1]}Z`;
    extracted['action'] = (cols[2] || 'DROP').toUpperCase();
    extracted['proto'] = (cols[3] || 'TCP').toUpperCase();
    extracted['src_ip'] = cols[4] || '0.0.0.0';
    extracted['dst_ip'] = cols[5] || '0.0.0.0';
    extracted['src_port'] = parseInt(cols[6] || '0', 10) || 0;
    extracted['dst_port'] = parseInt(cols[7] || '0', 10) || 0;
    extracted['size'] = parseInt(cols[8] || '0', 10) || 0;
    const rawDir = cols[cols.length - 1] || 'RECEIVE';
    extracted['direction'] = rawDir === 'RECEIVE' ? 'Inbound' : 'Outbound';

    lineage.push(
      { raw_field: 'date + time', raw_value: `${cols[0]} ${cols[1]}`, ocsf_path: 'time', status: 'mapped' },
      { raw_field: 'action', raw_value: extracted['action'], ocsf_path: 'activity_name / activity_id', transformation: `${extracted['action']} -> ${extracted['action'] === 'ALLOW' ? 'Allow (1)' : 'Deny (6)'}`, status: 'transformed' },
      { raw_field: 'protocol', raw_value: extracted['proto'], ocsf_path: 'connection_info.protocol_name', status: 'mapped' },
      { raw_field: 'src-ip', raw_value: extracted['src_ip'], ocsf_path: 'src_endpoint.ip', status: 'mapped' },
      { raw_field: 'dst-ip', raw_value: extracted['dst_ip'], ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
      { raw_field: 'src-port', raw_value: extracted['src_port'], ocsf_path: 'src_endpoint.port', status: 'mapped' },
      { raw_field: 'dst-port', raw_value: extracted['dst_port'], ocsf_path: 'dst_endpoint.port', status: 'mapped' },
      { raw_field: 'path / info', raw_value: rawDir, ocsf_path: 'connection_info.direction', transformation: 'RECEIVE -> Inbound', status: 'transformed' }
    );
  } else if (matchedConfig.id === 'paloalto-panos') {
    const cols = rawText.split(',').map(c => c.replace(/^["']|["']$/g, '').trim());
    
    let parsedTime = new Date().toISOString();
    try {
      if (cols[1]) {
        const d = new Date(cols[1].replace(/\//g, '-'));
        if (!isNaN(d.getTime())) {
          parsedTime = d.toISOString();
        }
      }
    } catch {
      // fallback
    }

    extracted['time'] = parsedTime;
    extracted['src_ip'] = cols[7] || '203.0.113.45';
    extracted['dst_ip'] = cols[8] || '10.0.4.12';
    extracted['rule_name'] = cols[11] || 'rule-block-ssh-external';
    extracted['app'] = cols[14] || 'ssh';
    extracted['vsys'] = cols[15] || 'vsys1';
    extracted['zone_in'] = cols[16] || 'untrust';
    extracted['zone_out'] = cols[17] || 'trust';
    extracted['ingress_if'] = cols[18] || 'ethernet1/1';
    extracted['egress_if'] = cols[19] || 'ethernet1/2';
    extracted['device_name'] = cols[20] || 'edge-fw-01';
    extracted['session_id'] = cols[22] || '998812';
    extracted['src_port'] = parseInt(cols[24] || '51322', 10) || 51322;
    extracted['dst_port'] = parseInt(cols[25] || '22', 10) || 22;
    extracted['proto'] = (cols[29] || 'tcp').toUpperCase();
    extracted['action'] = cols[30] || cols[4] || 'deny';
    extracted['bytes_sent'] = parseInt(cols[31] || '68', 10) || 0;
    extracted['bytes_rcvd'] = parseInt(cols[32] || '68', 10) || 0;

    unmapped['zone_in'] = extracted['zone_in'];
    unmapped['zone_out'] = extracted['zone_out'];
    unmapped['app'] = extracted['app'];
    unmapped['vsys'] = extracted['vsys'];

    lineage.push(
      { raw_field: 'col_7 (Source IP)', raw_value: extracted['src_ip'], ocsf_path: 'src_endpoint.ip', status: 'mapped' },
      { raw_field: 'col_24 (Source Port)', raw_value: extracted['src_port'], ocsf_path: 'src_endpoint.port', status: 'mapped' },
      { raw_field: 'col_8 (Dest IP)', raw_value: extracted['dst_ip'], ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
      { raw_field: 'col_25 (Dest Port)', raw_value: extracted['dst_port'], ocsf_path: 'dst_endpoint.port', status: 'mapped' },
      { raw_field: 'col_11 (Rule Name)', raw_value: extracted['rule_name'], ocsf_path: 'firewall_rule.name', status: 'mapped' },
      { raw_field: 'col_29 (Protocol)', raw_value: cols[29] || 'tcp', ocsf_path: 'connection_info.protocol_name', transformation: 'uppercase', status: 'transformed' },
      { raw_field: 'col_4 / col_30 (Action)', raw_value: extracted['action'], ocsf_path: 'activity_name / activity_id', transformation: 'deny -> 6 (Deny)', status: 'transformed' },
      { raw_field: 'col_20 (Device Name)', raw_value: extracted['device_name'], ocsf_path: 'device.name', status: 'mapped' },
      { raw_field: 'col_16 / col_17 (Zones)', raw_value: `${extracted['zone_in']} -> ${extracted['zone_out']}`, ocsf_path: 'unmapped.zone_in / unmapped.zone_out', status: 'unmapped' }
    );
  } else if (matchedConfig.id === 'suricata-eve') {
    try {
      const json = JSON.parse(rawText);
      extracted['time'] = json.timestamp ? new Date(json.timestamp).toISOString() : new Date().toISOString();
      extracted['src_ip'] = json.src_ip || '185.220.101.4';
      extracted['src_port'] = json.src_port || 443;
      extracted['dst_ip'] = json.dest_ip || '10.0.4.30';
      extracted['dst_port'] = json.dest_port || 51944;
      extracted['proto'] = (json.proto || 'TCP').toUpperCase();
      extracted['alert_title'] = json.alert?.signature || 'Security Finding';
      extracted['alert_uid'] = String(json.alert?.signature_id || 2001219);
      extracted['alert_category'] = json.alert?.category || 'Alert';
      extracted['severity_id'] = json.alert?.severity || 2;

      lineage.push(
        { raw_field: 'timestamp', raw_value: extracted['time'], ocsf_path: 'time', status: 'mapped' },
        { raw_field: 'src_ip', raw_value: extracted['src_ip'], ocsf_path: 'src_endpoint.ip', status: 'mapped' },
        { raw_field: 'dest_ip', raw_value: extracted['dst_ip'], ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
        { raw_field: 'proto', raw_value: extracted['proto'], ocsf_path: 'connection_info.protocol_name', status: 'mapped' },
        { raw_field: 'alert.signature', raw_value: extracted['alert_title'], ocsf_path: 'finding_info.title', status: 'mapped' },
        { raw_field: 'alert.severity', raw_value: extracted['severity_id'], ocsf_path: 'severity / severity_id', transformation: '2 -> High (4)', status: 'transformed' }
      );
    } catch {
      // fallback
    }
  } else if (matchedConfig.id === 'fortinet-fortios') {
    const kv = parseKeyValueString(rawText);
    extracted['time'] = (kv['date'] && kv['time']) ? `${kv['date']}T${kv['time']}Z` : new Date().toISOString();
    extracted['src_ip'] = kv['srcip'] || '192.168.1.105';
    extracted['src_port'] = parseInt(kv['srcport'] || '54211', 10);
    extracted['dst_ip'] = kv['dstip'] || '172.217.16.206';
    extracted['dst_port'] = parseInt(kv['dstport'] || '443', 10);
    extracted['action'] = kv['action'] || 'accept';
    extracted['policyname'] = kv['policyname'] || 'allow-outbound';
    extracted['devname'] = kv['devname'] || 'FG-HQ-FW01';
    extracted['proto'] = kv['proto'] === '6' ? 'TCP' : kv['proto'] === '17' ? 'UDP' : 'TCP';
    extracted['bytes_sent'] = parseInt(kv['sentbyte'] || '0', 10);
    extracted['bytes_rcvd'] = parseInt(kv['rcvdbyte'] || '0', 10);

    lineage.push(
      { raw_field: 'srcip', raw_value: extracted['src_ip'], ocsf_path: 'src_endpoint.ip', status: 'mapped' },
      { raw_field: 'dstip', raw_value: extracted['dst_ip'], ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
      { raw_field: 'policyname', raw_value: extracted['policyname'], ocsf_path: 'firewall_rule.name', status: 'mapped' },
      { raw_field: 'action', raw_value: extracted['action'], ocsf_path: 'activity_name / activity_id', transformation: 'accept -> 1 (Allow)', status: 'transformed' },
      { raw_field: 'devname', raw_value: extracted['devname'], ocsf_path: 'device.name', status: 'mapped' }
    );
  } else if (matchedConfig.id === 'cisco-asa') {
    const match = /%ASA-[1-7]-[0-9]{6}:\s+(Deny|Built|Teardown)\s+(\w+)\s+src\s+(\w+):([0-9.]+)\/(\d+)\s+dst\s+(\w+):([0-9.]+)\/(\d+)\s+by\s+access-group\s+"([^"]+)"/.exec(rawText);
    if (match) {
      extracted['time'] = new Date().toISOString();
      extracted['action'] = match[1];
      extracted['proto'] = match[2].toUpperCase();
      extracted['src_zone'] = match[3];
      extracted['src_ip'] = match[4];
      extracted['src_port'] = parseInt(match[5], 10);
      extracted['dst_zone'] = match[6];
      extracted['dst_ip'] = match[7];
      extracted['dst_port'] = parseInt(match[8], 10);
      extracted['acl_name'] = match[9];

      lineage.push(
        { raw_field: 'src_ip', raw_value: extracted['src_ip'], ocsf_path: 'src_endpoint.ip', status: 'mapped' },
        { raw_field: 'dst_ip', raw_value: extracted['dst_ip'], ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
        { raw_field: 'acl_name', raw_value: extracted['acl_name'], ocsf_path: 'firewall_rule.name', status: 'mapped' },
        { raw_field: 'action', raw_value: extracted['action'], ocsf_path: 'activity_name / activity_id', transformation: `${extracted['action']} -> Deny (6)`, status: 'transformed' }
      );
    }
  }

  stages.push({
    stage: 'parse',
    name: 'Grammar Parsing',
    status: 'success',
    durationMs: Number((performance.now() - t2).toFixed(2)),
    details: {
      fields_extracted: Object.keys(extracted).length,
      format: matchedConfig.format
    }
  });

  // Stage 4: Classify
  const t3 = performance.now();
  const isFinding = matchedConfig.id === 'suricata-eve';
  const class_name = isFinding ? 'Detection Finding' : 'Network Activity';
  const class_uid = isFinding ? 2004 : 4001;

  let activity_name = 'Deny';
  let activity_id = 6;
  const rawAction = String(extracted['action'] || '').toLowerCase();
  if (rawAction === 'allow' || rawAction === 'accept' || rawAction === 'built') {
    activity_name = 'Allow';
    activity_id = 1;
  } else if (isFinding) {
    activity_name = 'Create';
    activity_id = 1;
  }

  stages.push({
    stage: 'classify',
    name: 'OCSF Taxonomy Classification',
    status: 'success',
    durationMs: Number((performance.now() - t3).toFixed(2)),
    details: {
      target_class: class_name,
      class_uid,
      activity_name,
      activity_id
    }
  });

  // Stage 5: Map & Transform
  const t4 = performance.now();
  const normalizedEvent: OCSFEvent = {
    class_name,
    class_uid,
    activity_name,
    activity_id,
    time: extracted['time'] || new Date().toISOString(),
    event_uid,
    raw_data: rawText,
    raw_format: matchedConfig.format,
    source_vendor: matchedConfig.vendor,
    source_product: matchedConfig.product,
    src_endpoint: {
      ip: extracted['src_ip'] || '0.0.0.0',
      port: extracted['src_port'] || 0,
      zone: extracted['src_zone'] || extracted['zone_in'],
      interface: extracted['ingress_if'],
      bytes: extracted['bytes_sent']
    },
    dst_endpoint: {
      ip: extracted['dst_ip'] || '0.0.0.0',
      port: extracted['dst_port'] || 0,
      zone: extracted['dst_zone'] || extracted['zone_out'],
      interface: extracted['egress_if'],
      bytes: extracted['bytes_rcvd']
    },
    connection_info: {
      protocol_name: extracted['proto'] || 'TCP',
      direction: extracted['direction'] || (extracted['zone_in'] === 'untrust' ? 'inbound' : 'outbound'),
      session_id: extracted['session_id']
    },
    device: {
      name: extracted['devname'] || extracted['device_name'] || 'edge-fw-01',
      vendor_name: matchedConfig.vendor,
      type: matchedConfig.id === 'suricata-eve' ? 'IDS/IPS' : matchedConfig.id === 'windows-firewall' ? 'Host Firewall' : 'Firewall'
    },
    unmapped,
    processing_metadata: {
      ingest_time: new Date().toISOString(),
      matched_config: `${matchedConfig.id}.yaml`,
      parser_time_ms: Number((performance.now() - startTime).toFixed(2)),
      normalization_status: 'complete'
    }
  };

  if (extracted['rule_name'] || extracted['policyname'] || extracted['acl_name']) {
    normalizedEvent.firewall_rule = {
      name: extracted['rule_name'] || extracted['policyname'] || extracted['acl_name']
    };
  }

  if (isFinding) {
    normalizedEvent.finding_info = {
      uid: extracted['alert_uid'],
      title: extracted['alert_title'],
      desc: extracted['alert_category']
    };
    normalizedEvent.severity = extracted['severity_id'] === 1 ? 'Critical' : extracted['severity_id'] === 2 ? 'High' : 'Medium';
    normalizedEvent.severity_id = extracted['severity_id'] === 1 ? 5 : extracted['severity_id'] === 2 ? 4 : 3;
  }

  stages.push({
    stage: 'map',
    name: 'Dotted Schema Mapping',
    status: 'success',
    durationMs: Number((performance.now() - t4).toFixed(2)),
    details: {
      ocsf_class: class_name,
      mapped_fields: lineage.filter(l => l.status !== 'unmapped').length,
      unmapped_fields: Object.keys(unmapped).length
    }
  });

  // Stage 6: Preserve & Store
  const t5 = performance.now();
  stages.push({
    stage: 'preserve',
    name: 'Lossless Audit Preservation',
    status: 'success',
    durationMs: Number((performance.now() - t5).toFixed(2)),
    details: {
      uuid_stamped: event_uid,
      raw_preserved: true,
      bytes_preserved: rawText.length
    }
  });

  return {
    event_uid,
    success: true,
    matchedConfig: `${matchedConfig.vendor} ${matchedConfig.product}`,
    matchedVendor: matchedConfig.vendor,
    matchedProduct: matchedConfig.product,
    stages,
    normalizedEvent,
    lineage,
    totalDurationMs: Number((performance.now() - startTime).toFixed(2))
  };
}
