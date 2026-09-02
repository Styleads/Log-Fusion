import React, { useState } from 'react';
import { CheckCircle2, AlertTriangle, Layers, Activity, Eye, ShieldCheck } from 'lucide-react';
import { ValidationMetrics } from '../../types/assistant';
import { OCSFEvent } from '../../types/ocsf';

interface ValidationPreviewProps {
  detectedFormat: string;
  confidenceScore: number;
  confidenceLabel: 'high' | 'medium' | 'low';
  validation: ValidationMetrics;
  ocsfPreview: OCSFEvent[];
  onOpenDrilldown?: (event: OCSFEvent) => void;
}

export const ValidationPreview: React.FC<ValidationPreviewProps> = ({
  detectedFormat,
  confidenceScore,
  confidenceLabel,
  validation,
  ocsfPreview,
  onOpenDrilldown,
}) => {
  const [activeTab, setActiveTab] = useState<'ocsf' | 'lineage'>('ocsf');
  const sampleEvent = ocsfPreview[0];

  const confidenceBadgeColor =
    confidenceLabel === 'high'
      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
      : confidenceLabel === 'medium'
      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      : 'bg-rose-500/20 text-rose-300 border-rose-500/40';

  return (
    <div className="bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl overflow-hidden flex flex-col h-full">
      {/* Top Status & Metrics Bar */}
      <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 font-mono text-xs">
            <span className="text-slate-400">Detected Format:</span>
            <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 uppercase font-bold">
              {detectedFormat}
            </span>
          </div>

          <div className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono border font-semibold ${confidenceBadgeColor}`}>
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{Math.round(confidenceScore * 100)}% Confidence ({confidenceLabel})</span>
          </div>
        </div>

        {/* Tab Toggle: OCSF JSON vs Field Lineage */}
        <div className="flex items-center p-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('ocsf')}
            className={`px-3 py-1 rounded-md transition-all ${
              activeTab === 'ocsf' ? 'bg-cyan-500 text-white font-bold shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            OCSF JSON Preview
          </button>
          <button
            onClick={() => setActiveTab('lineage')}
            className={`px-3 py-1 rounded-md transition-all ${
              activeTab === 'lineage' ? 'bg-cyan-500 text-white font-bold shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Field Lineage Breakdown
          </button>
        </div>
      </div>

      {/* Validation Health Banner */}
      <div className="px-4 py-2.5 bg-slate-950/60 border-b border-slate-800/80 flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2">
          {validation.valid ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          )}
          <span className="text-slate-200">
            Pipeline Run: <b>{validation.successful_events} / {validation.total_lines}</b> sample lines normalized successfully (<b>{Math.round(validation.mapping_rate * 100)}%</b> rate)
          </span>
        </div>

        <span className="text-emerald-400 text-[11px] font-semibold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
          100% Lossless Raw Preservation
        </span>
      </div>

      {/* Main Preview Content */}
      <div className="p-4 flex-1 bg-slate-950/80 overflow-auto font-mono text-xs">
        {activeTab === 'ocsf' ? (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Normalized OCSF Document Preview:
              </span>
              {sampleEvent && onOpenDrilldown && (
                <button
                  onClick={() => onOpenDrilldown(sampleEvent)}
                  className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 px-2.5 py-1 rounded-lg border border-cyan-500/30 cursor-pointer"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Inspect Forensic Side-by-Side</span>
                </button>
              )}
            </div>

            <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300/90 whitespace-pre-wrap leading-relaxed overflow-x-auto select-text">
              {JSON.stringify(sampleEvent || ocsfPreview, null, 2)}
            </pre>
          </div>
        ) : (
          <div className="space-y-3">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block">
              Extracted Raw Attributes ➔ OCSF Dotted Schema Mapping:
            </span>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {Object.entries(validation.field_lineage || {}).map(([ocsfPath, sampleValue], idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col gap-1 hover:border-cyan-500/40 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 font-mono">{ocsfPath}</span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                      Mapped
                    </span>
                  </div>
                  <span className="text-xs text-slate-300 font-mono truncate">
                    Sample: <code className="text-slate-100">{String(sampleValue)}</code>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
