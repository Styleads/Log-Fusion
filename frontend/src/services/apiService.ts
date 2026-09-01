import { OCSFEvent } from '../types/ocsf';
import { INITIAL_MOCK_EVENTS } from '../data/mockEvents';
import { processRawLog } from './ocsfEngine';
import { ChatMessage } from '../types/chat';
import { queryGroundedRAG } from './ragService';

export interface BackendStatus {
  connected: boolean;
  url: string;
  version?: string;
  eventCount?: number;
  lastChecked: string;
}

const API_BASE_URL = '/api';

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
   * Check backend health status
   */
  async checkHealth(): Promise<BackendStatus> {
    if (this.useMockOnly) {
      return {
        connected: false,
        url: 'http://localhost:8000 (Mock Mode Active)',
        lastChecked: new Date().toISOString()
      };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(`${API_BASE_URL}/health`, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      if (res.ok) {
        const data = await res.json();
        return {
          connected: true,
          url: 'http://localhost:8000',
          version: data.version || '1.0.0-ocsf',
          eventCount: data.event_count || this.localEvents.length,
          lastChecked: new Date().toISOString()
        };
      }
    } catch {
      // Backend unreachable
    }

    return {
      connected: false,
      url: 'http://localhost:8000 (Standalone Mock)',
      lastChecked: new Date().toISOString()
    };
  }

  /**
   * Fetch all normalized OCSF events
   */
  async getEvents(): Promise<OCSFEvent[]> {
    if (!this.useMockOnly) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1500);
        const res = await fetch(`${API_BASE_URL}/events`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            return data;
          }
        }
      } catch {
        // fallback to local events
      }
    }
    return [...this.localEvents];
  }

  /**
   * Ingest a raw log line via backend or local engine
   */
  async ingestRaw(rawText: string): Promise<OCSFEvent> {
    if (!this.useMockOnly) {
      try {
        const res = await fetch(`${API_BASE_URL}/ingest`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ raw_log: rawText })
        });
        if (res.ok) {
          const event = await res.json();
          this.localEvents.unshift(event);
          return event;
        }
      } catch {
        // fallback to local engine
      }
    }

    // Fallback to local engine
    const pipelineResult = processRawLog(rawText);
    if (pipelineResult.normalizedEvent) {
      this.localEvents.unshift(pipelineResult.normalizedEvent);
      return pipelineResult.normalizedEvent;
    }
    throw new Error(pipelineResult.error || 'Failed to normalize event');
  }

  /**
   * AI Chatbot RAG query against Person E endpoint or local grounded analyzer
   */
  async sendChatMessage(userText: string, currentEvents: OCSFEvent[]): Promise<ChatMessage> {
    if (!this.useMockOnly) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`${API_BASE_URL}/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt: userText, context_events: currentEvents.slice(0, 50) }),
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
            citations: reply.citations,
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
   * Reset local dataset to default mock
   */
  resetLocalEvents(): OCSFEvent[] {
    this.localEvents = [...INITIAL_MOCK_EVENTS];
    return this.localEvents;
  }
}

export const apiService = new ApiService();
