import React, { useState } from 'react';
import { LayoutGrid, ListFilter, AlertCircle, Sparkles, Database } from 'lucide-react';
import { OCSFEvent } from '../../types/ocsf';
import { EventCard } from './EventCard';

interface EventFeedProps {
  events: OCSFEvent[];
  onSelectEvent: (event: OCSFEvent) => void;
  selectedEventId?: string;
  onOpenIngestLab: () => void;
}

export const EventFeed: React.FC<EventFeedProps> = ({
  events,
  onSelectEvent,
  selectedEventId,
  onOpenIngestLab
}) => {
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');

  return (
    <div className="space-y-3">
      {/* Header toolbar for Feed */}
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            Unified Event Stream
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            ({events.length} {events.length === 1 ? 'record' : 'records'})
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* View Mode Toggle */}
          <div className="flex items-center bg-slate-900/90 rounded-lg border border-slate-800 p-0.5">
            <button
              onClick={() => setViewMode('cards')}
              className={`p-1 rounded text-xs transition-colors ${viewMode === 'cards' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`}
              title="Card View (Standardized across vendors)"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`p-1 rounded text-xs transition-colors ${viewMode === 'table' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`}
              title="Compact Table View"
            >
              <ListFilter className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Feed Contents */}
      {events.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 bg-slate-900/40 rounded-xl border border-slate-800/80 text-center">
          <AlertCircle className="w-10 h-10 text-slate-500 mb-3" />
          <h4 className="text-base font-semibold text-slate-300">No normalized events match current filter</h4>
          <p className="text-xs text-slate-400 max-w-sm mt-1 mb-4">
            Try adjusting your search query, OCSF class selection, or vendor filters.
          </p>
          <button
            onClick={onOpenIngestLab}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30 transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Open Live Ingest Lab
          </button>
        </div>
      ) : viewMode === 'cards' ? (
        <div className="grid grid-cols-1 gap-2.5">
          {events.map((event) => (
            <EventCard
              key={event.event_uid}
              event={event}
              onSelect={onSelectEvent}
              isSelected={event.event_uid === selectedEventId}
            />
          ))}
        </div>
      ) : (
        /* Compact Table View */
        <div className="overflow-x-auto rounded-xl border border-slate-800/90 bg-slate-900/70 shadow-md">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">OCSF Class</th>
                <th className="py-2.5 px-3">Action / Severity</th>
                <th className="py-2.5 px-3">Rule / Signature</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Dest Endpoint</th>
                <th className="py-2.5 px-3">Vendor / Device</th>
                <th className="py-2.5 px-3">UUID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {events.map((e) => (
                <tr
                  key={e.event_uid}
                  onClick={() => onSelectEvent(e)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                >
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">{new Date(e.time).toLocaleTimeString()}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap font-medium text-cyan-300">{e.class_name}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      e.activity_name === 'Deny' ? 'bg-rose-500/20 text-rose-300' :
                      e.activity_name === 'Allow' ? 'bg-emerald-500/20 text-emerald-300' :
                      'bg-purple-500/20 text-purple-300'
                    }`}>
                      {e.severity || e.activity_name}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 max-w-[200px] truncate text-slate-200">
                    {e.finding_info?.title || e.firewall_rule?.name}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">{e.src_endpoint?.ip}:{e.src_endpoint?.port}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">{e.dst_endpoint?.ip}:{e.dst_endpoint?.port}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">{e.device.vendor_name}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap text-[10px] text-cyan-500">{e.event_uid.substring(0, 8)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
