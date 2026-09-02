import React, { useState } from 'react';
import { X, Settings, Server, Trash2, Sparkles, Database, Save, CheckCircle2, ShieldCheck, ToggleLeft, ToggleRight } from 'lucide-react';
import { BackendStatus } from '../../services/apiService';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  mockMode: boolean;
  onToggleMockMode: () => void;
  backendStatus: BackendStatus;
  onResetEvents: () => void;
  realDataOnly: boolean;
  onToggleRealDataOnly: () => void;
  onSeedMockData: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  mockMode,
  onToggleMockMode,
  backendStatus,
  onResetEvents,
  realDataOnly,
  onToggleRealDataOnly,
  onSeedMockData
}) => {
  const [activeTab, setActiveTab] = useState<'general' | 'engine' | 'ai' | 'siem'>('general');
  const [backendUrl, setBackendUrl] = useState('http://localhost:8000');
  const [aiModel, setAiModel] = useState('grounded-rag');
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [siemIndex, setSiemIndex] = useState('ulpf-events');

  if (!isOpen) return null;

  const handleSave = () => {
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 800);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl rounded-3xl bg-[#0e111d] border border-slate-700 shadow-2xl shadow-purple-950/40 overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-[#131627] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-2xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
              <Settings className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                LogFusion Settings & Configuration
              </h3>
              <p className="text-xs text-slate-400">
                Manage data store preferences, backend endpoints, and AI engine
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-2xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Strip */}
        <div className="flex items-center gap-2 px-6 py-2 bg-slate-950/60 border-b border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('general')}
            className={`px-3 py-1.5 rounded-xl transition-all cursor-pointer ${activeTab === 'general' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'}`}
          >
            Data Store & Theme
          </button>
          <button
            onClick={() => setActiveTab('engine')}
            className={`px-3 py-1.5 rounded-xl transition-all cursor-pointer ${activeTab === 'engine' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'}`}
          >
            Normalization Engine
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`px-3 py-1.5 rounded-xl transition-all cursor-pointer ${activeTab === 'ai' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'text-slate-400 hover:text-white'}`}
          >
            Joi AI Assistant
          </button>
          <button
            onClick={() => setActiveTab('siem')}
            className={`px-3 py-1.5 rounded-xl transition-all cursor-pointer ${activeTab === 'siem' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'}`}
          >
            SIEM & Data Lake
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5 text-xs text-slate-300">
          
          {/* TAB: GENERAL */}
          {activeTab === 'general' && (
            <div className="space-y-5">
              {/* Real Data Only Toggle */}
              <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <span className="font-bold text-white text-xs font-mono">
                      Real Data Only Mode
                    </span>
                    <p className="text-[11px] text-slate-400">
                      When enabled, all fallback mock/demo logs are stripped out. The dashboard, feeds, and analytics will exclusively display real logs ingested into OpenSearch.
                    </p>
                  </div>
                  <button
                    onClick={onToggleRealDataOnly}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl font-mono text-xs font-bold border transition-all cursor-pointer ${
                      realDataOnly
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {realDataOnly ? (
                      <>
                        <ToggleRight className="w-4 h-4 text-cyan-400" />
                        <span>Real Only (Active)</span>
                      </>
                    ) : (
                      <>
                        <ToggleLeft className="w-4 h-4 text-slate-500" />
                        <span>Demo Mode (Mock Data)</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Database Actions */}
              <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-3">
                <label className="font-semibold text-white uppercase text-[11px] font-mono block">
                  Database & Storage Operations
                </label>
                <p className="text-[11px] text-slate-400">
                  Wipe all records from the OpenSearch database cluster (`ulpf-events` index) or seed starter mock events.
                </p>

                <div className="flex flex-wrap gap-2.5 pt-1">
                  <button
                    onClick={() => {
                      onResetEvents();
                      setSavedSuccess(true);
                      setTimeout(() => setSavedSuccess(false), 1500);
                    }}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-950/50 hover:bg-rose-900/50 text-rose-300 border border-rose-800/60 font-semibold transition-all cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                    <span>Wipe OpenSearch & Clear Data</span>
                  </button>

                  <button
                    onClick={() => {
                      onSeedMockData();
                      setSavedSuccess(true);
                      setTimeout(() => setSavedSuccess(false), 1500);
                    }}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-purple-950/40 hover:bg-purple-900/40 text-purple-300 border border-purple-800/50 font-semibold transition-all cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                    <span>Seed Demo Multi-Vendor Logs</span>
                  </button>
                </div>
              </div>

              {/* Theme Preset */}
              <div className="space-y-1.5">
                <label className="font-semibold text-white uppercase text-[11px] font-mono">
                  Theme Preset
                </label>
                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div className="p-3 rounded-2xl bg-[#141726] border-2 border-cyan-400 shadow-glow-cyan flex items-center justify-between">
                    <div>
                      <p className="font-bold text-white">Modern Obsidian (Active)</p>
                      <p className="text-[10px] text-slate-400">Midnight dark with neon accents</p>
                    </div>
                    <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="p-3 rounded-2xl bg-[#0a0a0f] border border-slate-800 opacity-60 cursor-not-allowed">
                    <p className="font-bold text-slate-300">OLED Pitch Black</p>
                    <p className="text-[10px] text-slate-500">Pure monochrome 100% black</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: NORMALIZATION ENGINE */}
          {activeTab === 'engine' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">Pipeline Execution Mode</span>
                  <button
                    onClick={onToggleMockMode}
                    className={`px-3 py-1.5 rounded-xl font-mono text-xs border transition-all cursor-pointer ${
                      mockMode
                        ? 'bg-amber-950/40 text-amber-300 border-amber-500/40'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-500/40'
                    }`}
                  >
                    {mockMode ? 'Standalone Engine (In-Memory)' : 'Live FastAPI Backend (:8001 / :8000)'}
                  </button>
                </div>
                <p className="text-slate-400">
                  Standalone Mode executes parsing, OCSF classification, and UUID stamping entirely in the browser. Live Mode forwards batches to the Python FastAPI backend engine and indexes to OpenSearch.
                </p>
              </div>

              <div className="space-y-1.5 pt-2">
                <label className="font-semibold text-white">FastAPI Backend URL</label>
                <input
                  type="text"
                  value={backendUrl}
                  onChange={(e) => setBackendUrl(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}

          {/* TAB: JOI AI ASSISTANT */}
          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="font-semibold text-white">AI Inference & RAG Provider</label>
                <select
                  value={aiModel}
                  onChange={(e) => setAiModel(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-purple-300 focus:outline-none focus:border-purple-500"
                >
                  <option value="grounded-rag">LogFusion Grounded In-Memory RAG (Air-Gapped / Offline)</option>
                  <option value="ollama-llama3">Local Ollama Llama 3 8B (Air-Gapped)</option>
                  <option value="gemini-flash">Gemini Flash Cloud Endpoint</option>
                </select>
                <p className="text-slate-400">
                  The Grounded In-Memory RAG engine evaluates all threat hunting queries directly over the active OCSF dataset with deterministic citations.
                </p>
              </div>
            </div>
          )}

          {/* TAB: SIEM & DATA LAKE */}
          {activeTab === 'siem' && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="font-semibold text-white">Export Index / Topic Name</label>
                <input
                  type="text"
                  value={siemIndex}
                  onChange={(e) => setSiemIndex(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />
                <p className="text-slate-400">
                  Target OpenSearch/Elasticsearch index (`ulpf-events`) for automated NDJSON streaming.
                </p>
              </div>
            </div>
          )}

        </div>

        {/* Footer with Save */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-[#131627] flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            LogFusion v1.1.0 · Configuration Active
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              Close
            </button>

            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30 transition-all cursor-pointer"
            >
              {savedSuccess ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Save className="w-4 h-4" />}
              <span>{savedSuccess ? 'Saved!' : 'Save Preferences'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
