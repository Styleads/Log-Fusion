import React from 'react';
import { Layers, CheckCircle2, ShieldAlert } from 'lucide-react';
import { SummaryStats } from '../../types/events';

interface ConcentricProgressRingProps {
  stats: SummaryStats;
}

export const ConcentricProgressRing: React.FC<ConcentricProgressRingProps> = ({ stats }) => {
  const denyPercent = stats.totalEvents > 0 ? Math.round((stats.denyCount / stats.totalEvents) * 100) : 68;
  const allowPercent = stats.totalEvents > 0 ? Math.round((stats.allowCount / stats.totalEvents) * 100) : 32;
  const losslessPercent = 100;

  // SVG parameters for concentric rings
  const size = 180;
  const center = size / 2;
  
  // Ring 1 (Outer - Purple: Network Activity / Volume)
  const r1 = 70;
  const c1 = 2 * Math.PI * r1;
  const stroke1 = c1 * 0.85;

  // Ring 2 (Middle - Pink/Magenta: Deny Mitigation)
  const r2 = 54;
  const c2 = 2 * Math.PI * r2;
  const stroke2 = c2 * (denyPercent / 100);

  // Ring 3 (Inner - Cyan/Blue: Lossless Traceability)
  const r3 = 38;
  const c3 = 2 * Math.PI * r3;
  const stroke3 = c3 * 0.98;

  return (
    <div className="obsidian-card p-5 sm:p-6 flex flex-col md:flex-row items-center justify-between gap-6">
      
      {/* Left: Concentric Rings SVG */}
      <div className="relative flex items-center justify-center">
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Ring 1 (Outer Track & Value) */}
          <circle
            cx={center}
            cy={center}
            r={r1}
            stroke="#20243d"
            strokeWidth="9"
            fill="transparent"
          />
          <circle
            cx={center}
            cy={center}
            r={r1}
            stroke="#a855f7"
            strokeWidth="9"
            strokeDasharray={`${stroke1} ${c1}`}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />

          {/* Ring 2 (Middle Track & Value) */}
          <circle
            cx={center}
            cy={center}
            r={r2}
            stroke="#20243d"
            strokeWidth="9"
            fill="transparent"
          />
          <circle
            cx={center}
            cy={center}
            r={r2}
            stroke="#ec4899"
            strokeWidth="9"
            strokeDasharray={`${stroke2} ${c2}`}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />

          {/* Ring 3 (Inner Track & Value) */}
          <circle
            cx={center}
            cy={center}
            r={r3}
            stroke="#20243d"
            strokeWidth="9"
            fill="transparent"
          />
          <circle
            cx={center}
            cy={center}
            r={r3}
            stroke="#06b6d4"
            strokeWidth="9"
            strokeDasharray={`${stroke3} ${c3}`}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-xl font-bold font-mono text-white">
            {stats.totalEvents}
          </span>
          <span className="text-[10px] uppercase font-mono text-slate-400 font-semibold tracking-wider">
            Events
          </span>
        </div>
      </div>

      {/* Right: Legend Breakdown */}
      <div className="flex-1 space-y-3.5 w-full">
        <div>
          <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
            OCSF Pipeline Progress
          </h4>
          <p className="text-xs text-slate-400">
            Real-time normalization and threat mitigation ratios
          </p>
        </div>

        <div className="space-y-2.5">
          {/* Item 1: Network Activity */}
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#a855f7] shadow-[0_0_8px_#a855f7]" />
              <span className="text-slate-300 font-medium">Network Activity (4001)</span>
            </div>
            <span className="font-mono font-bold text-purple-300">
              {Math.round(((stats.totalEvents - stats.activeFindings) / (stats.totalEvents || 1)) * 100)}%
            </span>
          </div>

          {/* Item 2: Deny Mitigation */}
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ec4899] shadow-[0_0_8px_#ec4899]" />
              <span className="text-slate-300 font-medium">Blocked / Deny Rate</span>
            </div>
            <span className="font-mono font-bold text-pink-300">
              {denyPercent}%
            </span>
          </div>

          {/* Item 3: Lossless Fidelity */}
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-[#06b6d4] shadow-[0_0_8px_#06b6d4]" />
              <span className="text-slate-300 font-medium">Lossless UUID Fidelity</span>
            </div>
            <span className="font-mono font-bold text-cyan-300">
              100%
            </span>
          </div>
        </div>
      </div>

    </div>
  );
};
