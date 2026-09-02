import React from 'react';
import { ShieldCheck, Server, RefreshCw, Settings } from 'lucide-react';
import { BackendStatus } from '../../services/apiService';

interface HeaderProps {
  backendStatus: BackendStatus;
  mockMode: boolean;
  onToggleMockMode: () => void;
  onResetEvents: () => void;
  totalEventsCount: number;
  onOpenSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  backendStatus,
  mockMode,
  onToggleMockMode,
  onResetEvents,
  onOpenSettings
}) => {
  return (
    <header className="w-full py-4 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        
        {/* Left: Branding & Greeting */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-2xl bg-gradient-to-tr from-purple-600 to-indigo-600 shadow-glow-purple border border-purple-400/30">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400 font-medium">Hello,</span>
              <h2 className="text-base sm:text-lg font-bold text-white tracking-tight flex items-center gap-1 font-sans">
                LogFusion SOC <span className="text-sm">🔥</span>
              </h2>
            </div>
            <p className="text-[10px] font-mono text-cyan-400">
              OCSF v1.1.0 · Schema Normalization Engine
            </p>
          </div>
        </div>

        {/* Right Controls: Mode Switcher + Reset + Settings */}
        <div className="flex items-center gap-2.5">
          {/* Mode Switcher */}
          <button
            onClick={onToggleMockMode}
            title={mockMode ? "Running in Standalone Engine. Click to connect to backend." : "Connected to Backend API"}
            className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-2xl text-xs font-mono border transition-all ${
              mockMode
                ? 'bg-[#141726] text-amber-300 border-amber-500/30 hover:border-amber-500/60'
                : backendStatus.connected
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/40'
                : 'bg-rose-950/40 text-rose-300 border-rose-500/40'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>{mockMode ? 'Standalone Engine' : ':8000 Live'}</span>
          </button>

          {/* Reset Dataset & OpenSearch Database */}
          <button
            onClick={onResetEvents}
            title="Reset dataset & wipe database"
            className="p-2 rounded-2xl bg-[#141726] hover:bg-[#1e233b] border border-white/5 text-slate-400 hover:text-cyan-400 transition-all cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          {/* Settings Button */}
          <button
            onClick={onOpenSettings}
            title="Open Settings & Configuration"
            className="p-2 rounded-2xl bg-[#141726] hover:bg-[#1e233b] border border-white/5 text-slate-300 hover:text-cyan-400 transition-all cursor-pointer"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>

      </div>
    </header>
  );
};
