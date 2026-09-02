import { OCSFEvent, OCSFClassName } from './ocsf';

export interface FilterState {
  searchQuery: string;
  selectedClass: 'ALL' | OCSFClassName;
  selectedVendor: string;
  selectedAction: string;
  selectedSeverity: string;
  timeRange: '15m' | '1h' | '24h' | '7d' | 'ALL' | 'CUSTOM';
  startDate?: string;
  endDate?: string;
  sortOrder?: 'desc' | 'asc';
  ipFilter: string;
  portFilter: string;
}

export interface SummaryStats {
  totalEvents: number;
  activeSources: number;
  denyCount: number;
  allowCount: number;
  activeFindings: number;
  losslessPreservationRate: number;
  vendorCounts: Record<string, number>;
  classCounts: Record<string, number>;
  eventsPerSecond: number;
}

export interface PipelineStageResult {
  stage: 'ingest' | 'detect' | 'parse' | 'classify' | 'map' | 'preserve' | 'store';
  name: string;
  status: 'pending' | 'running' | 'success' | 'warning' | 'error';
  durationMs?: number;
  details?: Record<string, any>;
  outputPreview?: any;
}

export interface NormalizationPipelineOutput {
  event_uid: string;
  success: boolean;
  stages: PipelineStageResult[];
  matchedVendor?: string;
  matchedProduct?: string;
  matchedConfig?: string;
  normalizedEvent?: OCSFEvent;
  lineage: Array<{
    raw_field: string;
    raw_value: any;
    ocsf_path: string;
    transformation?: string;
    status: 'mapped' | 'unmapped' | 'static' | 'transformed';
  }>;
  totalDurationMs: number;
  error?: string;
}
