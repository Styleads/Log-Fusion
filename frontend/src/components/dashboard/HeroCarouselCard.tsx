import React from 'react';
import { ShieldCheck, MoreHorizontal, ArrowUpRight, Zap, ShieldAlert } from 'lucide-react';
import { OCSFEvent } from '../../types/ocsf';

interface HeroCarouselCardProps {
  topEvent?: OCSFEvent;
  onInspect: (event: OCSFEvent) => void;
}

export const HeroCarouselCard: React.FC<HeroCarouselCardProps> = ({ topEvent, onInspect }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* Primary Highlighted Card (Blue-Cyan Gradient matching Screen 1) */}
      <div className="md:col-span-2 relative overflow-hidden rounded-3xl bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 p-5 sm:p-6 text-white shadow-xl shadow-blue-600/25 transition-transform hover:scale-[1.01]">
        {/* Background ambient bubble */}
        <div className="absolute -right-8 -bottom-8 w-44 h-44 rounded-full bg-white/10 blur-2xl pointer-events-none" />
        
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/20 backdrop-blur-md text-[11px] font-semibold tracking-wide text-white border border-white/20">
              <Zap className="w-3 h-3 text-cyan-200 fill-current" />
              ACTIVE PERIMETER SHIELD
            </span>
            <h3 className="text-xl sm:text-2xl font-bold tracking-tight text-white pt-2">
              SSH Reconnaissance Blocked
            </h3>
            <p className="text-xs sm:text-sm text-blue-100/90 max-w-md">
              Palo Alto PA-5220 successfully denied external brute-force vectors on port 22 with 100% OCSF telemetry fidelity.
            </p>
          </div>

          <button 
            onClick={() => topEvent && onInspect(topEvent)}
            className="p-2.5 rounded-2xl bg-white/15 hover:bg-white/25 backdrop-blur-md transition-all text-white border border-white/20"
            title="Inspect Event Lineage"
          >
            <MoreHorizontal className="w-5 h-5" />
          </button>
        </div>

        {/* Bottom Metadata Pills */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/15">
          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full bg-emerald-400/25 text-emerald-100 font-bold text-xs border border-emerald-300/30">
              TODAY
            </span>
            <span className="text-xs font-mono text-blue-100 font-medium">
              09:14:02 UTC
            </span>
          </div>

          {topEvent && (
            <button
              onClick={() => onInspect(topEvent)}
              className="flex items-center gap-1 text-xs font-semibold text-white bg-black/20 hover:bg-black/30 px-3.5 py-1.5 rounded-xl backdrop-blur-sm transition-all"
            >
              <span>Inspect OCSF JSON</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Secondary Companion Card (Dark Obsidian with Magenta/Pink accents) */}
      <div className="rounded-3xl bg-[#141726] border border-white/5 p-5 sm:p-6 flex flex-col justify-between shadow-card-soft">
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="px-3 py-1 rounded-full bg-pink-500/15 text-pink-300 font-semibold text-[11px] border border-pink-500/25">
              CRITICAL FINDING
            </span>
            <ShieldAlert className="w-4 h-4 text-pink-400" />
          </div>

          <h4 className="text-base font-bold text-slate-100 font-mono">
            SQL Injection Defended
          </h4>
          <p className="text-xs text-slate-400 mt-1">
            Suricata EVE IDS triggered on URI payload <code className="text-pink-300 bg-pink-950/40 px-1 rounded font-mono">UNION SELECT</code>
          </p>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
          <span className="text-slate-400 font-mono">10.0.4.80:80</span>
          <span className="text-cyan-400 font-semibold font-mono">45.33.32.156</span>
        </div>
      </div>
    </div>
  );
};
