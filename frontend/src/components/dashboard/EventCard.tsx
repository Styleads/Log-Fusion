import React from 'react';
import { ArrowRight, ShieldCheck, ShieldAlert, Check, Ban, ExternalLink } from 'lucide-react';
import { OCSFEvent } from '../../types/ocsf';

interface EventCardProps {
  event: OCSFEvent;
  onSelect: (event: OCSFEvent) => void;
  isSelected?: boolean;
}

export const EventCard: React.FC<EventCardProps> = ({ event, onSelect, isSelected = false }) => {
  const isDetection = event.class_name === 'Detection Finding';
  const isDeny = event.activity_name?.toLowerCase() === 'deny' || event.activity_name?.toLowerCase() === 'drop';
  const isAllow = event.activity_name?.toLowerCase() === 'allow' || event.activity_name?.toLowerCase() === 'accept';

  const timeFormatted = (() => {
    try {
      const d = new Date(event.time);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return event.time;
    }
  })();

  const titleOrRule = isDetection 
    ? (event.finding_info?.title || 'Security Detection Finding')
    : (event.firewall_rule?.name || 'default-firewall-rule');

  const srcStr = event.src_endpoint ? `${event.src_endpoint.ip}${event.src_endpoint.port ? `:${event.src_endpoint.port}` : ''}` : '0.0.0.0';
  const dstStr = event.dst_endpoint ? `${event.dst_endpoint.ip}${event.dst_endpoint.port ? `:${event.dst_endpoint.port}` : ''}` : '0.0.0.0';

  return (
    <div
      onClick={() => onSelect(event)}
      className={`p-4 sm:p-5 rounded-3xl border transition-all duration-200 cursor-pointer flex items-center justify-between gap-3 sm:gap-4 ${
        isSelected
          ? 'bg-[#1a1e35] border-cyan-400 shadow-glow-cyan'
          : isDetection
          ? 'bg-[#171424] hover:bg-[#1f1b33] border-purple-500/20 hover:border-purple-500/40'
          : isDeny
          ? 'bg-[#18131c] hover:bg-[#221827] border-pink-500/20 hover:border-pink-500/40'
          : 'bg-[#141726] hover:bg-[#1a1e32] border-white/5 hover:border-white/15'
      }`}
    >
      {/* Left side: Icon Pill + Details */}
      <div className="flex items-center gap-3.5 min-w-0">
        
        {/* Rounded Action Checkbox / Icon Pill (matching Screen 3) */}
        <div
          className={`flex-shrink-0 w-9 h-9 rounded-2xl flex items-center justify-center border shadow-sm ${
            isDetection
              ? 'bg-purple-500/20 text-purple-300 border-purple-500/40'
              : isDeny
              ? 'bg-pink-500/20 text-pink-300 border-pink-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
          }`}
        >
          {isDetection ? (
            <ShieldAlert className="w-4 h-4" />
          ) : isDeny ? (
            <Ban className="w-4 h-4" />
          ) : (
            <Check className="w-4 h-4 stroke-[3]" />
          )}
        </div>

        {/* Text Content */}
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h4 className="text-xs sm:text-sm font-bold text-slate-100 font-mono truncate">
              {titleOrRule}
            </h4>
            
            {/* OCSF Class Tag */}
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
              isDetection ? 'bg-purple-950/60 text-purple-300 border border-purple-800/40' : 'bg-slate-800 text-slate-300'
            }`}>
              {event.class_name}
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mt-1 flex-wrap">
            <span className="text-slate-200">{srcStr}</span>
            <ArrowRight className="w-3 h-3 text-slate-500" />
            <span className="text-slate-200">{dstStr}</span>
            {event.connection_info?.protocol_name && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 font-semibold">
                {event.connection_info.protocol_name}
              </span>
            )}
            <span className="text-slate-500 hidden sm:inline">· {event.device?.vendor_name}</span>
          </div>
        </div>

      </div>

      {/* Right side: Time Pill & Trigger */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className="text-[11px] font-mono px-3 py-1 rounded-full bg-slate-800/80 text-slate-300 border border-white/5">
          {timeFormatted}
        </span>
        <ExternalLink className="w-3.5 h-3.5 text-slate-500 hover:text-cyan-400 transition-colors hidden sm:block" />
      </div>
    </div>
  );
};
