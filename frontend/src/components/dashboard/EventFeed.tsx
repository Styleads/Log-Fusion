import React, { useState, useEffect, useMemo } from 'react';
import { LayoutGrid, ListFilter, AlertCircle, Sparkles, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
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
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(30);

  // Reset to page 1 whenever events dataset changes (due to filtering / new ingest)
  useEffect(() => {
    setCurrentPage(1);
  }, [events.length]);

  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));

  // Current page records slice
  const paginatedEvents = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    return events.slice(startIndex, startIndex + pageSize);
  }, [events, currentPage, pageSize]);

  const startRecord = events.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endRecord = Math.min(currentPage * pageSize, events.length);

  // Page navigation generator for numbered pills
  const pageNumbers = useMemo(() => {
    const pages: number[] = [];
    const maxVisible = 5;
    let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    let end = Math.min(totalPages, start + maxVisible - 1);
    if (end - start + 1 < maxVisible) {
      start = Math.max(1, end - maxVisible + 1);
    }
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    return pages;
  }, [currentPage, totalPages]);

  return (
    <div className="space-y-3">
      {/* Header toolbar for Feed */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            Unified Event Stream
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            ({events.length} {events.length === 1 ? 'record' : 'records'})
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Records per page selector */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
            <span>Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer text-xs"
            >
              <option value={15}>15</option>
              <option value={30}>30</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          {/* View Mode Toggle */}
          <div className="flex items-center bg-slate-900/90 rounded-lg border border-slate-800 p-0.5">
            <button
              onClick={() => setViewMode('cards')}
              className={`p-1.5 rounded text-xs transition-colors cursor-pointer ${viewMode === 'cards' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`}
              title="Card View (Standardized across vendors)"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`p-1.5 rounded text-xs transition-colors cursor-pointer ${viewMode === 'table' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`}
              title="Compact Table View"
            >
              <ListFilter className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Feed Contents */}
      {events.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 bg-slate-900/40 rounded-2xl border border-slate-800/80 text-center">
          <AlertCircle className="w-10 h-10 text-slate-500 mb-3" />
          <h4 className="text-base font-semibold text-slate-300">No normalized events match current filters</h4>
          <p className="text-xs text-slate-400 max-w-sm mt-1 mb-4 font-mono">
            Try adjusting your search query, date range, OCSF class selection, or vendor filters.
          </p>
          <button
            onClick={onOpenIngestLab}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30 transition-all cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Open Ingest Lab
          </button>
        </div>
      ) : viewMode === 'cards' ? (
        <div className="grid grid-cols-1 gap-2.5">
          {paginatedEvents.map((event) => (
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
        <div className="overflow-x-auto rounded-2xl border border-slate-800/90 bg-slate-900/70 shadow-md">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">OCSF Class</th>
                <th className="py-2.5 px-3">Action / Status</th>
                <th className="py-2.5 px-3">Rule / Signature</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Dest Endpoint</th>
                <th className="py-2.5 px-3">Vendor / Device</th>
                <th className="py-2.5 px-3">UUID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {paginatedEvents.map((e) => (
                <tr
                  key={e.event_uid}
                  onClick={() => onSelectEvent(e)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                >
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">{new Date(e.time).toLocaleTimeString()}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap font-medium text-cyan-300">{e.class_name}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      e.activity_name?.toLowerCase() === 'deny' || e.activity_name?.toLowerCase() === 'drop' ? 'bg-rose-500/20 text-rose-300' :
                      e.activity_name?.toLowerCase() === 'allow' || e.activity_name?.toLowerCase() === 'accept' ? 'bg-emerald-500/20 text-emerald-300' :
                      'bg-purple-500/20 text-purple-300'
                    }`}>
                      {e.severity || e.activity_name}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 max-w-[200px] truncate text-slate-200">
                    {e.finding_info?.title || e.firewall_rule?.name || '—'}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">{e.src_endpoint?.ip || '—'}:{e.src_endpoint?.port || '—'}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">{e.dst_endpoint?.ip || '—'}:{e.dst_endpoint?.port || '—'}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">{e.device?.vendor_name || e.source_vendor || 'Other'}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap text-[10px] text-cyan-500">{e.event_uid.substring(0, 8)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination Footer Controls */}
      {events.length > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 px-2 border-t border-slate-800/80 text-xs font-mono text-slate-400">
          <div>
            Showing <span className="font-bold text-slate-200">{startRecord}–{endRecord}</span> of <span className="font-bold text-slate-200">{events.length}</span> records
            {totalPages > 1 && ` · Page ${currentPage} of ${totalPages}`}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center gap-1.5">
              {/* First Page */}
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
                title="First Page"
              >
                <ChevronsLeft className="w-4 h-4" />
              </button>

              {/* Previous Page */}
              <button
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
                title="Previous Page"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>

              {/* Numbered Page Buttons */}
              {pageNumbers.map(p => (
                <button
                  key={p}
                  onClick={() => setCurrentPage(p)}
                  className={`w-7 h-7 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                    currentPage === p
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60 shadow-sm'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                  }`}
                >
                  {p}
                </button>
              ))}

              {/* Next Page */}
              <button
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
                title="Next Page"
              >
                <ChevronRight className="w-4 h-4" />
              </button>

              {/* Last Page */}
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
                title="Last Page"
              >
                <ChevronsRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
