import { OCSFEvent } from './ocsf';

export interface FieldLineage {
  [ocsfPath: string]: string | number | boolean | null;
}

export interface ValidationMetrics {
  valid: boolean;
  total_lines: number;
  successful_events: number;
  mapping_rate: number;
  field_lineage: FieldLineage;
  unmapped_fields?: string[];
  error?: string;
}

export interface AssistantAnalysisData {
  source_name: string;
  slug: string;
  detected_format: 'json' | 'key_value' | 'csv' | 'space_delimited' | 'syslog' | string;
  confidence_score: number;
  confidence_label: 'high' | 'medium' | 'low';
  yaml_draft: string;
  validation: ValidationMetrics;
  ocsf_preview: OCSFEvent[];
}

export interface AssistantAnalysisResponse {
  status: 'success' | 'error';
  data: AssistantAnalysisData;
  message?: string;
}

export interface DraftMappingItem {
  slug: string;
  source_name: string;
  vendor: string;
  product: string;
  format: string;
  status: 'draft' | 'reviewed';
  confidence?: 'high' | 'medium' | 'low';
  file_path: string;
  sample_count?: number;
  created_at?: string;
  yaml_content?: string;
}

export interface PresetSampleLog {
  id: string;
  name: string;
  vendor: string;
  deviceType: string;
  format: string;
  description: string;
  rawLines: string[];
}
