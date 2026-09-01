import React, { useState, useRef, useEffect } from 'react';
import { Send, Sparkles, Bot, User, ShieldAlert, ArrowRight, ExternalLink, RefreshCw, Terminal } from 'lucide-react';
import { ChatMessage, ChatCitation } from '../../types/chat';
import { OCSFEvent } from '../../types/ocsf';
import { apiService } from '../../services/apiService';
import { Badge } from '../common/Badge';

interface SecurityChatbotProps {
  events: OCSFEvent[];
  onOpenDrilldown: (event: OCSFEvent) => void;
}

export const SecurityChatbot: React.FC<SecurityChatbotProps> = ({ events, onOpenDrilldown }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      timestamp: new Date().toISOString(),
      text: `Hello! I am **Joi**, your LogFusion Security Assistant, grounded directly in the normalized OCSF event store (${events.length} active perimeter events).\n\nYou can ask me natural language threat hunting questions, anomaly queries, or cross-vendor correlation checks.`,
      suggestedFollowUps: [
        'Any repeated SSH scans from 185.220.101.4?',
        'Show all Deny events across firewalls',
        'What are the active detection findings?',
        'Compare Palo Alto vs Suricata vs Fortinet volumes'
      ]
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isSending]);

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || inputText;
    if (!query.trim() || isSending) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      timestamp: new Date().toISOString(),
      text: query
    };

    setMessages(prev => [...prev, userMessage]);
    setInputText('');
    setIsSending(true);

    try {
      const response = await apiService.sendChatMessage(query, events);
      setMessages(prev => [...prev, response]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          sender: 'assistant',
          timestamp: new Date().toISOString(),
          text: `⚠️ Unable to process query against backend. Grounded in-memory analysis fallback error: ${err}`
        }
      ]);
    } finally {
      setIsSending(false);
    }
  };

  const handleCitationClick = (citation: ChatCitation) => {
    const found = events.find(e => e.event_uid === citation.event_uid);
    if (found) {
      onOpenDrilldown(found);
    }
  };

  return (
    <div className="flex flex-col h-[76vh] bg-slate-900/90 rounded-2xl border border-slate-800 backdrop-blur-xl shadow-2xl overflow-hidden">
      
      {/* Chatbot Header */}
      <div className="flex items-center justify-between px-5 py-3.5 bg-slate-950/90 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/15 text-purple-400 border border-purple-500/30">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white font-mono">
                Joi · AI Security RAG Assistant
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/40">
                Grounded OCSF Store
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Correlating across Palo Alto, Suricata, Fortinet, and Cisco telemetry
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            setMessages([
              {
                id: `reset-${Date.now()}`,
                sender: 'assistant',
                timestamp: new Date().toISOString(),
                text: 'Chat history cleared. Grounded query engine ready.',
                suggestedFollowUps: [
                  'Any repeated SSH scans from 185.220.101.4?',
                  'Show all Deny events across firewalls',
                  'What are the active detection findings?'
                ]
              }
            ]);
          }}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          title="Clear conversation"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Messages Feed */}
      <div className="flex-1 p-4 sm:p-5 overflow-y-auto space-y-4">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';

          return (
            <div
              key={msg.id}
              className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
            >
              {/* Avatar */}
              <div
                className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center border ${
                  isUser
                    ? 'bg-cyan-600 text-white border-cyan-400/40'
                    : 'bg-purple-950/80 text-purple-300 border-purple-700/50'
                }`}
              >
                {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div className={`max-w-[85%] sm:max-w-[75%] space-y-2.5 ${isUser ? 'items-end' : 'items-start'}`}>
                <div
                  className={`p-3.5 sm:p-4 rounded-2xl text-xs sm:text-sm leading-relaxed shadow-md ${
                    isUser
                      ? 'bg-cyan-600 text-white font-medium rounded-tr-none'
                      : 'bg-slate-950/90 text-slate-200 border border-slate-800 rounded-tl-none font-sans'
                  }`}
                >
                  <div className="whitespace-pre-wrap font-sans markdown-body">
                    {msg.text}
                  </div>
                </div>

                {/* Event Citations Pill List */}
                {msg.citations && msg.citations.length > 0 && (
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold uppercase tracking-wider text-purple-400">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Grounded Event Citations ({msg.citations.length})</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {msg.citations.map((c) => (
                        <button
                          key={c.event_uid}
                          onClick={() => handleCitationClick(c)}
                          className="flex items-center justify-between p-2 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/50 text-left transition-all group"
                        >
                          <div className="truncate pr-2">
                            <p className="text-[11px] font-medium text-slate-200 truncate group-hover:text-cyan-300">
                              {c.summary}
                            </p>
                            <p className="text-[10px] font-mono text-slate-500">
                              {c.vendor} · {c.event_uid.substring(0, 8)}...
                            </p>
                          </div>
                          <ExternalLink className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 flex-shrink-0" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Suggested Follow-ups */}
                {msg.suggestedFollowUps && msg.suggestedFollowUps.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {msg.suggestedFollowUps.map((suggestion, sIdx) => (
                      <button
                        key={sIdx}
                        onClick={() => handleSendMessage(suggestion)}
                        className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-slate-950 text-cyan-400 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-900 transition-all flex items-center gap-1"
                      >
                        <ArrowRight className="w-2.5 h-2.5" />
                        <span>{suggestion}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {/* Thinking Indicator */}
        {isSending && (
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center bg-purple-950/80 text-purple-300 border border-purple-700/50">
              <Bot className="w-4 h-4" />
            </div>
            <div className="p-3.5 rounded-2xl rounded-tl-none bg-slate-950 border border-slate-800 flex items-center gap-2 text-xs font-mono text-purple-400">
              <Sparkles className="w-4 h-4 animate-spin text-purple-400" />
              <span>Retrieving & synthesizing over normalized OCSF event store...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Chat Input Bar */}
      <div className="p-3.5 bg-slate-950/90 border-t border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Ask Joi anything about blocked traffic, SSH scans, threat signatures, or IPs..."
            className="flex-1 px-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 font-sans"
          />
          <button
            type="submit"
            disabled={!inputText.trim() || isSending}
            className="p-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-md shadow-purple-600/30"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>

    </div>
  );
};
