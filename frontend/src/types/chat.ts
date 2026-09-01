import { OCSFEvent } from './ocsf';

export interface ChatCitation {
  event_uid: string;
  vendor: string;
  class_name: string;
  summary: string;
  timestamp: string;
  src_ip?: string;
  dst_ip?: string;
  activity_name?: string;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  timestamp: string;
  text: string;
  citations?: ChatCitation[];
  highlightedEvents?: OCSFEvent[];
  structuredData?: {
    type: 'stats_table' | 'ip_breakdown' | 'rule_summary' | 'threat_alert';
    data: any;
  };
  suggestedFollowUps?: string[];
  isThinking?: boolean;
}
