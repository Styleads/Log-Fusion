import React, { useState } from 'react';
import { Search, Filter, Play, Pause, Download, X, Calendar, ArrowDownUp, Clock } from 'lucide-react';
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
  const [showDatePicker, setShowDatePicker] = useState(false);

  const hasActiveFilters = 
    filters.searchQuery !== '' ||
    filters.selectedClass !== 'ALL' ||
    filters.selectedVendor !== 'ALL' ||
    filters.selectedAction !== 'ALL' ||
    filters.selectedSeverity !== 'ALL' ||
    filters.timeRange !== 'ALL' ||
    Boolean(filters.startDate) ||
    Boolean(filters.endDate);

  const toggleSortOrder = () => {
    const nextSort = filters.sortOrder === 'asc' ? 'desc' : 'asc';
    onFilterChange({ sortOrder: nextSort });
  };

  return (
    <div className="bg-slate-900/90 p-4 rounded-2xl border border-slate-800/90 shadow-md backdrop-blur-md space-y-3">
      {/* Top row: Search input + Stream control + Sort button + Export */}
      <div className="flex flex-col sm:flex-row items-center gap-2.5">
        {/* Search Input */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, Port, Rule, Threat Signature, or UUID..."
            value={filters.searchQuery}
            onChange={(e) => onFilterChange({ searchQuery: e.target.value })}
            className="w-full pl-9 pr-8 py-2 bg-slate-950/80 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
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

        {/* Sort by Date Toggle */}
        <button
          onClick={toggleSortOrder}
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800/80 text-cyan-300 border border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800 transition-all whitespace-nowrap cursor-pointer"
          title={`Currently sorted ${filters.sortOrder === 'asc' ? 'Oldest to Newest' : 'Newest to Oldest'}. Click to toggle.`}
        >
          <ArrowDownUp className="w-3.5 h-3.5 text-cyan-400" />
          <span>{filters.sortOrder === 'asc' ? 'Oldest First' : 'Newest First'}</span>
        </button>

        {/* Live Stream Simulation Button */}
        <button
          onClick={onToggleStreaming}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold tracking-wide border transition-all whitespace-nowrap cursor-pointer ${
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
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800/80 text-cyan-300 border border-cyan-800/40 hover:border-cyan-500/60 hover:bg-slate-800 transition-all whitespace-nowrap cursor-pointer"
          title="Export current filtered normalized event view as OCSF NDJSON"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export NDJSON</span>
        </button>
      </div>

      {/* Bottom row: Filter Selectors + Date Range Filter */}
      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
        <div className="flex items-center gap-1 text-slate-400 font-semibold uppercase tracking-wider text-[10px] mr-1">
          <Filter className="w-3 h-3 text-cyan-400" />
          <span>Filters:</span>
        </div>

        {/* OCSF Class Filter */}
        <select
          value={filters.selectedClass}
          onChange={(e) => onFilterChange({ selectedClass: e.target.value as 'ALL' | OCSFClassName })}
          className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
        >
          <option value="ALL">All OCSF Classes</option>
          <option value="Network Activity">Network Activity (4001)</option>
          <option value="Detection Finding">Detection Finding (2004)</option>
        </select>

        {/* Vendor Filter */}
        <select
          value={filters.selectedVendor}
          onChange={(e) => onFilterChange({ selectedVendor: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
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
          className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
        >
          <option value="ALL">All Actions</option>
          <option value="Deny">Deny / Blocked</option>
          <option value="Allow">Allow / Forwarded</option>
          <option value="Create">Detection Alerts</option>
        </select>

        {/* Severity Filter */}
        <select
          value={filters.selectedSeverity}
          onChange={(e) => onFilterChange({ selectedSeverity: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500 text-xs cursor-pointer"
        >
          <option value="ALL">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        {/* Date Range Preset Selector */}
        <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-xl px-2 py-1">
          <Calendar className="w-3.5 h-3.5 text-cyan-400" />
          <select
            value={filters.timeRange}
            onChange={(e) => {
              const val = e.target.value as FilterState['timeRange'];
              if (val === 'CUSTOM') {
                setShowDatePicker(true);
                onFilterChange({ timeRange: val });
              } else {
                setShowDatePicker(false);
                onFilterChange({ timeRange: val, startDate: undefined, endDate: undefined });
              }
            }}
            className="bg-transparent text-slate-300 focus:outline-none text-xs cursor-pointer"
          >
            <option value="ALL">All Dates</option>
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="CUSTOM">Custom Range...</option>
          </select>
        </div>

        {/* Custom Date Range Inputs Toggle */}
        {(showDatePicker || filters.timeRange === 'CUSTOM') && (
          <div className="flex items-center gap-1.5 bg-slate-950 border border-cyan-500/40 rounded-xl px-2.5 py-1 animate-fade-in">
            <span className="text-[10px] text-slate-400 font-mono">From:</span>
            <input
              type="date"
              value={filters.startDate || ''}
              onChange={(e) => onFilterChange({ startDate: e.target.value, timeRange: 'CUSTOM' })}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-0.5 text-[11px] font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
            <span className="text-[10px] text-slate-400 font-mono">To:</span>
            <input
              type="date"
              value={filters.endDate || ''}
              onChange={(e) => onFilterChange({ endDate: e.target.value, timeRange: 'CUSTOM' })}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-0.5 text-[11px] font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
            />
          </div>
        )}

        {/* Reset Filters Button */}
        {hasActiveFilters && (
          <button
            onClick={() => {
              setShowDatePicker(false);
              onResetFilters();
            }}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] bg-rose-950/40 text-rose-300 border border-rose-800/50 hover:bg-rose-900/60 transition-colors ml-auto cursor-pointer"
          >
            <X className="w-3 h-3" />
            <span>Reset filters</span>
          </button>
        )}
      </div>
    </div>
  );
};
