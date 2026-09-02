import { OCSFEvent } from '../types/ocsf';
import { INITIAL_MOCK_EVENTS } from '../data/mockEvents';
import { processRawLog } from './ocsfEngine';
import { ChatMessage } from '../types/chat';
import { queryGroundedRAG } from './ragService';

export interface BackendStatus {
  connected: boolean;
  engineOnline?: boolean;
  storageOnline?: boolean;
  url: string;
  version?: string;
  eventCount?: number;
  lastChecked: string;
}

const STORAGE_API_BASE = '/api';
const ENGINE_API_BASE = '/engine-api';

class ApiService {
  private useMockOnly: boolean = false;
  private localEvents: OCSFEvent[] = [...INITIAL_MOCK_EVENTS];

  public setMockMode(forceMock: boolean) {
    this.useMockOnly = forceMock;
  }

  public getMockMode(): boolean {
    return this.useMockOnly;
  }

  /**
   * Check backend health status across Engine and Storage APIs
   */
  async checkHealth(): Promise<BackendStatus> {
    if (this.useMockOnly) {
      return {
        connected: false,
        engineOnline: false,
        storageOnline: false,
        url: 'http://localhost:8001 (Standalone Engine)',
        lastChecked: new Date().toISOString()
      };
    }

    let engineOnline = false;
    let storageOnline = false;
    let version = '1.0.0-ocsf';

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);

      // Check Engine API
      const engineRes = await fetch(`${ENGINE_API_BASE}/health`, { signal: controller.signal });
      if (engineRes.ok) {
        const data = await engineRes.json();
        if (data.status === 'ok') {
          engineOnline = true;
          version = data.version || version;
        }
      }

      // Check Storage API
      const storageRes = await fetch(`${STORAGE_API_BASE}/health`, { signal: controller.signal });
      if (storageRes.ok) {
        const data = await storageRes.json();
        if (data.status === 'ok') {
          storageOnline = true;
        }
      }

      clearTimeout(timeoutId);
    } catch {
      // Backend unreachable
    }

    const connected = engineOnline || storageOnline;

    return {
      connected,
      engineOnline,
      storageOnline,
      url: connected ? 'http://localhost:8001 / :8000' : 'http://localhost:8001 (Offline)',
      version,
      eventCount: this.localEvents.length,
      lastChecked: new Date().toISOString()
    };
  }

  /**
   * Fetch all normalized OCSF events from Storage API or local memory
   */
  async getEvents(): Promise<OCSFEvent[]> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${STORAGE_API_BASE}/events/search?limit=100`, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.events) && data.events.length > 0) {
          const mappedEvents: OCSFEvent[] = data.events.map((hit: any) => {
            const norm = hit.normalized_event && typeof hit.normalized_event === 'object' ? hit.normalized_event : hit;
            let rawStr = '';
            if (typeof hit.raw_event === 'string') {
              rawStr = hit.raw_event;
            } else if (hit.raw_event && typeof hit.raw_event.raw_data === 'string') {
              rawStr = hit.raw_event.raw_data;
            } else if (norm && typeof norm.raw_data === 'string') {
              rawStr = norm.raw_data;
            }

            return {
              ...norm,
              event_uid: hit.event_id || norm.event_uid || norm.metadata?.uid || `gen-${Math.random()}`,
              raw_data: rawStr,
              raw_format: norm.raw_format || hit.provenance?.format || 'raw',
              source_vendor: norm.source_vendor || norm.device?.vendor_name || hit.provenance?.vendor || 'Unknown Vendor',
              source_product: norm.source_product || norm.device?.type || 'Security Device'
            };
          });

          // Merge backend events with local memory events, avoiding duplicates by event_uid
          const map = new Map<string, OCSFEvent>();
          for (const ev of [...mappedEvents, ...this.localEvents]) {
            if (ev && ev.event_uid) {
              map.set(ev.event_uid, ev);
            }
          }
          this.localEvents = Array.from(map.values());
          return this.localEvents;
        }
      }
    } catch (err) {
      console.warn('Storage API events search failed, using local events', err);
    }

    return [...this.localEvents];
  }

  /**
   * Ingest a raw log line via live Engine API with storage forwarding
   */
  async ingestRaw(rawText: string): Promise<OCSFEvent> {
    try {
      const res = await fetch(`${ENGINE_API_BASE}/api/v1/ingest/line`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_line: rawText, forward_to_storage: true })
      });

      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && data.event) {
          const event: OCSFEvent = {
            ...data.event,
            event_uid: data.uid || data.event.metadata?.uid || `gen-${Date.now()}`
          };
          this.localEvents.unshift(event);
          return event;
        }
      }
    } catch {
      // Fallback to local engine
    }

    // Local TypeScript Fallback Engine
    const pipelineResult = processRawLog(rawText);
    if (pipelineResult.normalizedEvent) {
      this.localEvents.unshift(pipelineResult.normalizedEvent);
      return pipelineResult.normalizedEvent;
    }

    throw new Error(pipelineResult.error || 'Failed to normalize log line');
  }

  /**
   * Ingest a batch of log lines via live Engine API with storage forwarding
   */
  async ingestBatch(rawLines: string[]): Promise<OCSFEvent[]> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${ENGINE_API_BASE}/api/v1/ingest/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_lines: rawLines, forward_to_storage: true }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && Array.isArray(data.events) && data.events.length > 0) {
          const mappedEvents: OCSFEvent[] = data.events.map((ev: any) => ({
            ...ev,
            event_uid: ev.metadata?.uid || `gen-${Date.now()}`
          }));
          this.localEvents = [...mappedEvents, ...this.localEvents];
          return mappedEvents;
        }
      }
    } catch (err) {
      console.warn('Backend batch ingest failed, falling back to local engine', err);
    }

    // Local TypeScript Fallback Engine
    const results: OCSFEvent[] = [];
    for (const line of rawLines) {
      if (!line.trim()) continue;
      try {
        const res = processRawLog(line);
        if (res.normalizedEvent) {
          results.push(res.normalizedEvent);
        }
      } catch (err) {
        console.error('Local parsing failed for line:', line, err);
      }
    }

    if (results.length > 0) {
      this.localEvents = [...results, ...this.localEvents];
    }
    return results;
  }

  /**
   * AI Chatbot RAG query against Unified Gateway API or local grounded analyzer
   */
  async sendChatMessage(userText: string, currentEvents: OCSFEvent[]): Promise<ChatMessage> {
    if (!this.useMockOnly) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const res = await fetch(`${ENGINE_API_BASE}/api/v1/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            prompt: userText,
            context_events: currentEvents.slice(0, 50)
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const reply = await res.json();
          return {
            id: `msg-${Date.now()}`,
            sender: 'assistant',
            timestamp: new Date().toISOString(),
            text: reply.text || reply.answer,
            citations: reply.citations || [],
            structuredData: reply.structuredData
          };
        }
      } catch {
        // Fallback to grounded local analyzer
      }
    }

    // Local Grounded RAG Query Engine
    return queryGroundedRAG(userText, currentEvents);
  }

  /**
   * Run Anomaly Detection across normalized events
   */
  async runAnomalyDetection(events?: OCSFEvent[]): Promise<any[]> {
    if (!this.useMockOnly) {
      try {
        const res = await fetch(`${ENGINE_API_BASE}/api/v1/anomalies/run`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ events: events || this.localEvents })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'success' && Array.isArray(data.anomalies)) {
            return data.anomalies;
          }
        }
      } catch {
        // Fallback
      }
    }

    return [];
  }

  /**
   * Reset local dataset to default mock
   */
  resetLocalEvents(): OCSFEvent[] {
    this.localEvents = [...INITIAL_MOCK_EVENTS];
    return this.localEvents;
  }
}

export const apiService = new ApiService();
