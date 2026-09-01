import React from 'react';
import { Home, BarChart2, Plus, Calendar, MessageSquare, Sparkles, Terminal } from 'lucide-react';

interface BottomDockProps {
  activeTab: 'dashboard' | 'analytics' | 'ingest' | 'chat' | 'docs';
  setActiveTab: (tab: 'dashboard' | 'analytics' | 'ingest' | 'chat' | 'docs') => void;
  onOpenIngestModal: () => void;
}

export const BottomDock: React.FC<BottomDockProps> = ({
  activeTab,
  setActiveTab,
  onOpenIngestModal
}) => {
  return (
    <div className="fixed bottom-5 left-1/2 -translate-x-1/2 z-50">
      <div className="flex items-center gap-1.5 sm:gap-3 px-4 py-2.5 rounded-full bg-[#121422]/90 backdrop-blur-xl border border-white/10 shadow-dock">
        
        {/* Tab 1: Overview */}
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`p-3 rounded-full transition-all duration-200 ${
            activeTab === 'dashboard'
              ? 'text-white bg-white/10 shadow-inner'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
          title="Overview & SOC Feed"
        >
          <Home className="w-5 h-5" />
        </button>

        {/* Tab 2: Statistics & Telemetry */}
        <button
          onClick={() => setActiveTab('analytics')}
          className={`p-3 rounded-full transition-all duration-200 ${
            activeTab === 'analytics'
              ? 'text-cyan-300 bg-cyan-500/15 shadow-inner'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
          title="Statistics & Concentric Rings"
        >
          <BarChart2 className="w-5 h-5" />
        </button>

        {/* Center Glowing Purple + Action Button */}
        <button
          onClick={onOpenIngestModal}
          className="mx-1 p-3.5 rounded-full glow-dock-btn text-white hover:scale-110 active:scale-95 transition-all duration-200 cursor-pointer shadow-lg shadow-purple-600/50"
          title="Instant Log Ingest & Normalization Lab"
        >
          <Plus className="w-6 h-6 stroke-[2.5]" />
        </button>

        {/* Tab 3: OCSF Docs & Mapping */}
        <button
          onClick={() => setActiveTab('docs')}
          className={`p-3 rounded-full transition-all duration-200 ${
            activeTab === 'docs'
              ? 'text-white bg-white/10 shadow-inner'
              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
          }`}
          title="OCSF Docs & YAML Rules"
        >
          <Calendar className="w-5 h-5" />
        </button>

        {/* Tab 4: Denji AI Chatbot */}
        <button
          onClick={() => setActiveTab('chat')}
          className={`p-3 rounded-full transition-all duration-200 ${
            activeTab === 'chat'
              ? 'text-purple-300 bg-purple-500/20 shadow-inner'
              : 'text-slate-400 hover:text-purple-300 hover:bg-white/5'
          }`}
          title="Ask Joi AI"
        >
          <MessageSquare className="w-5 h-5" />
        </button>

      </div>
    </div>
  );
};
