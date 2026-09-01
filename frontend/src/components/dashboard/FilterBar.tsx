import React from 'react';
import { Search, Filter, Play, Pause, Download, X } from 'lucide-react';
import { FilterState } from '../../types/events';
import { OCSFClassName } from '../../types/ocsf';

interface FilterBarProps {
  filters: FilterState;
  onFilterChange: (filters: Partial<FilterState>) => void;
  onResetFilters: () => void;
  isLiveStreaming: boolean;
  onToggleStreaming: () => void;
  onExportNDJSON: () => void;
  availableVendors: string[];
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  onFilterChange,
  onResetFilters,
  isLiveStreaming,
  onToggleStreaming,
  onExportNDJSON,
  availableVendors
}) => {
  const hasActiveFilters = 
    filters.searchQuery !== '' ||
    filters.selectedClass !== 'ALL' ||
    filters.selectedVendor !== 'ALL' ||
    filters.selectedAction !== 'ALL' ||
    filters.selectedSeverity !== 'ALL';

  return (
    <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800/90 shadow-md backdrop-blur-md space-y-3">
      {/* Top row: Search input + Stream control + Export */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, Port, Rule name, Threat Signature, or Event UUID..."
            value={filters.searchQuery}
            onChange={(e) => onFilterChange({ searchQuery: e.target.value })}
            className="w-full pl-9 pr-8 py-2 bg-slate-950/80 border border-slate-800 rounded-lg text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
          />
          {filters.searchQuery && (
            <button
              onClick={() => onFilterChange({ searchQuery: '' })}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Live Stream Simulation Button */}
        <button
          onClick={onToggleStreaming}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide border transition-all whitespace-nowrap ${
            isLiveStreaming
              ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
              : 'bg-slate-800/80 text-slate-300 border-slate-700 hover:bg-slate-800'
          }`}
        >
          {isLiveStreaming ? (
            <>
              <Pause className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              <span>Live Ingesting</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 text-slate-400" />
              <span>Simulate Stream</span>
            </>
          )}
        </button>

        {/* Export to NDJSON */}
        <button
          onClick={onExportNDJSON}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800/80 text-cyan-300 border border-cyan-800/40 hover:border-cyan-500/60 hover:bg-slate-800 transition-all whitespace-nowrap"
          title="Export current normalized event view as OCSF NDJSON for SIEM / Data Lake"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export NDJSON</span>
        </button>
      </div>

      {/* Bottom row: Filter Selectors */}
      <div className="flex flex-wrap items-center gap-2.5 pt-1 text-xs">
        <div className="flex items-center gap-1 text-slate-400 font-semibold uppercase tracking-wider text-[10px] mr-1">
          <Filter className="w-3 h-3" />
          <span>Filters:</span>
        </div>

        {/* OCSF Class Filter */}
        <select
          value={filters.selectedClass}
          onChange={(e) => onFilterChange({ selectedClass: e.target.value as 'ALL' | OCSFClassName })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs"
        >
          <option value="ALL">All OCSF Classes</option>
          <option value="Network Activity">Network Activity (4001)</option>
          <option value="Detection Finding">Detection Finding (2004)</option>
        </select>

        {/* Vendor Filter */}
        <select
          value={filters.selectedVendor}
          onChange={(e) => onFilterChange({ selectedVendor: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs"
        >
          <option value="ALL">All Perimeter Vendors</option>
          {availableVendors.map(v => (
            <option key={v} value={v}>{v}</option>
          ))}
        </select>

        {/* Action / Severity Filter */}
        <select
          value={filters.selectedAction}
          onChange={(e) => onFilterChange({ selectedAction: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs"
        >
          <option value="ALL">All Actions / Statuses</option>
          <option value="Deny">Deny / Blocked</option>
          <option value="Allow">Allow / Forwarded</option>
          <option value="Create">Detection Alerts (Create)</option>
        </select>

        {/* Severity Filter */}
        <select
          value={filters.selectedSeverity}
          onChange={(e) => onFilterChange({ selectedSeverity: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs"
        >
          <option value="ALL">All Severities</option>
          <option value="Critical">Critical Severity</option>
          <option value="High">High Severity</option>
          <option value="Medium">Medium Severity</option>
          <option value="Low">Low Severity</option>
        </select>

        {/* Reset Filters Pill */}
        {hasActiveFilters && (
          <button
            onClick={onResetFilters}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] bg-rose-950/40 text-rose-300 border border-rose-800/50 hover:bg-rose-900/60 transition-colors ml-auto"
          >
            <X className="w-3 h-3" />
            <span>Reset filters</span>
          </button>
        )}
      </div>
    </div>
  );
};
