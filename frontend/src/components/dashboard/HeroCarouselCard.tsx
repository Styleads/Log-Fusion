import React from 'react';
import { ShieldCheck, MoreHorizontal, ArrowUpRight, Zap, ShieldAlert, CheckCircle2, Upload, Sparkles } from 'lucide-react';
import { OCSFEvent } from '../../types/ocsf';

interface HeroCarouselCardProps {
  events?: OCSFEvent[];
  topEvent?: OCSFEvent;
  onInspect: (event: OCSFEvent) => void;
  onOpenIngest?: () => void;
}

export const HeroCarouselCard: React.FC<HeroCarouselCardProps> = ({
  events = [],
  topEvent: propTopEvent,
  onInspect,
  onOpenIngest
}) => {
  const primaryEvent = propTopEvent || events[0];

  // Find the highest-priority security finding or deny event
  const alertEvent = events.find(
    e => e.class_name === 'Detection Finding' || e.activity_name?.toLowerCase() === 'deny' || e.activity_name?.toLowerCase() === 'drop'
  ) || (events.length > 1 ? events[1] : null);

  // If no events exist in dataset (0 events)
  if (!primaryEvent) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="md:col-span-2 relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-indigo-950/60 to-slate-900 p-6 text-white border border-slate-800 shadow-xl flex flex-col justify-between min-h-[190px]">
          <div className="flex items-start justify-between">
            <div className="space-y-1.5">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-300 text-[11px] font-mono font-semibold border border-cyan-500/30">
                <Sparkles className="w-3.5 h-3.5" />
                PIPELINE READY
              </span>
              <h3 className="text-xl sm:text-2xl font-bold tracking-tight text-white pt-1">
                Awaiting Telemetry Ingestion
              </h3>
              <p className="text-xs sm:text-sm text-slate-300 max-w-md">
                Drop any raw perimeter firewall, IDS, or proxy log file to normalize into standardized OCSF v1.1.0 schema events in real-time.
              </p>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">0 events in active buffer</span>
            {onOpenIngest && (
              <button
                onClick={onOpenIngest}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30 transition-all cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Open Ingest Lab</span>
              </button>
            )}
          </div>
        </div>

        <div className="rounded-3xl bg-[#141726] border border-white/5 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-300 font-semibold text-[11px] border border-emerald-500/25">
                STATUS
              </span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <h4 className="text-base font-bold text-slate-100 font-mono">
              Perimeter Engine Nominal
            </h4>
            <p className="text-xs text-slate-400 mt-1">
              Universal Log Parser & Normalization Framework is ready to process log streams.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono text-cyan-400">
            Storage Layer: OpenSearch 9200
          </div>
        </div>
      </div>
    );
  }

  // Formatting values from live primary event
  const isDeny = primaryEvent.activity_name?.toLowerCase() === 'deny' || primaryEvent.activity_name?.toLowerCase() === 'drop';
  const isFinding = primaryEvent.class_name === 'Detection Finding';
  const primaryTitle = isFinding
    ? (primaryEvent.finding_info?.title || 'Security Detection Finding')
    : primaryEvent.firewall_rule?.name
    ? `Rule: ${primaryEvent.firewall_rule.name}`
    : `${primaryEvent.activity_name || 'Processed'} Perimeter Session`;

  const primaryVendor = primaryEvent.source_vendor || primaryEvent.device?.vendor_name || 'Firewall';
  const primaryTime = (() => {
    try {
      return new Date(primaryEvent.time).toLocaleTimeString();
    } catch {
      return primaryEvent.time;
    }
  })();

  const srcIp = primaryEvent.src_endpoint?.ip || '0.0.0.0';
  const dstIp = primaryEvent.dst_endpoint?.ip || '0.0.0.0';

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* Primary Highlighted Card */}
      <div className="md:col-span-2 relative overflow-hidden rounded-3xl bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 p-5 sm:p-6 text-white shadow-xl shadow-blue-600/25 transition-transform hover:scale-[1.01]">
        <div className="absolute -right-8 -bottom-8 w-44 h-44 rounded-full bg-white/10 blur-2xl pointer-events-none" />
        
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/20 backdrop-blur-md text-[11px] font-semibold tracking-wide text-white border border-white/20">
              <Zap className="w-3 h-3 text-cyan-200 fill-current" />
              LATEST PERIMETER EVENT ({primaryEvent.class_name})
            </span>
            <h3 className="text-xl sm:text-2xl font-bold tracking-tight text-white pt-2 truncate max-w-lg">
              {primaryTitle}
            </h3>
            <p className="text-xs sm:text-sm text-blue-100/90 max-w-md">
              {primaryVendor} {isDeny ? 'blocked connection attempt' : 'authorized traffic'} from <code className="bg-white/15 px-1 rounded font-mono">{srcIp}</code> to <code className="bg-white/15 px-1 rounded font-mono">{dstIp}</code>.
            </p>
          </div>

          <button 
            onClick={() => onInspect(primaryEvent)}
            className="p-2.5 rounded-2xl bg-white/15 hover:bg-white/25 backdrop-blur-md transition-all text-white border border-white/20 cursor-pointer"
            title="Inspect Event Lineage"
          >
            <MoreHorizontal className="w-5 h-5" />
          </button>
        </div>

        {/* Bottom Metadata Pills */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/15">
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-full font-bold text-xs border ${
              isDeny
                ? 'bg-rose-500/30 text-rose-100 border-rose-400/40'
                : 'bg-emerald-400/25 text-emerald-100 border-emerald-300/30'
            }`}>
              {primaryEvent.activity_name?.toUpperCase() || 'ACTIVITY'}
            </span>
            <span className="text-xs font-mono text-blue-100 font-medium">
              {primaryTime}
            </span>
          </div>

          <button
            onClick={() => onInspect(primaryEvent)}
            className="flex items-center gap-1 text-xs font-semibold text-white bg-black/20 hover:bg-black/30 px-3.5 py-1.5 rounded-xl backdrop-blur-sm transition-all cursor-pointer"
          >
            <span>Inspect OCSF JSON</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Secondary Companion Card */}
      <div className="rounded-3xl bg-[#141726] border border-white/5 p-5 sm:p-6 flex flex-col justify-between shadow-card-soft">
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className={`px-3 py-1 rounded-full font-semibold text-[11px] border ${
              alertEvent?.class_name === 'Detection Finding'
                ? 'bg-pink-500/15 text-pink-300 border-pink-500/25'
                : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/25'
            }`}>
              {alertEvent?.class_name === 'Detection Finding' ? 'SECURITY ALERT' : 'PERIMETER STATUS'}
            </span>
            {alertEvent?.class_name === 'Detection Finding' ? (
              <ShieldAlert className="w-4 h-4 text-pink-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
            )}
          </div>

          <h4 className="text-base font-bold text-slate-100 font-mono truncate">
            {alertEvent?.finding_info?.title || alertEvent?.firewall_rule?.name || 'Perimeter Traffic Monitored'}
          </h4>
          <p className="text-xs text-slate-400 mt-1 line-clamp-2">
            {alertEvent ? (
              `${alertEvent.source_vendor || 'Device'} logged ${alertEvent.activity_name} on port ${alertEvent.dst_endpoint?.port || alertEvent.src_endpoint?.port || '—'}`
            ) : (
              '100% telemetry fidelity preserved into unified OCSF schema.'
            )}
          </p>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">{alertEvent?.dst_endpoint?.ip || '0.0.0.0'}</span>
          <span className="text-cyan-400 font-semibold">{alertEvent?.src_endpoint?.ip || '0.0.0.0'}</span>
        </div>
      </div>
    </div>
  );
};
