import React, { useState, useRef, useEffect, useMemo } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';
import { OCSFEvent } from '../../types/ocsf';
import { ChevronDown, Check, Calendar, Clock, BarChart3, Activity } from 'lucide-react';

interface VisualAnalyticsProps {
  events: OCSFEvent[];
}

type TimeRangeOption = 'Weeks' | 'Days' | 'Months';

export const VisualAnalytics: React.FC<VisualAnalyticsProps> = ({ events }) => {
  const [timeRange, setTimeRange] = useState<TimeRangeOption>('Days');
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Dynamically compute chart data from real event timestamps
  const activeData = useMemo(() => {
    if (events.length === 0) {
      if (timeRange === 'Days') {
        return [
          { name: '00:00', eps: 0, display: '00:00 UTC · 0 events', isPeak: false },
          { name: '04:00', eps: 0, display: '04:00 UTC · 0 events', isPeak: false },
          { name: '08:00', eps: 0, display: '08:00 UTC · 0 events', isPeak: false },
          { name: '12:00', eps: 0, display: '12:00 UTC · 0 events', isPeak: false },
          { name: '16:00', eps: 0, display: '16:00 UTC · 0 events', isPeak: false },
          { name: '20:00', eps: 0, display: '20:00 UTC · 0 events', isPeak: false },
          { name: '23:59', eps: 0, display: '23:59 UTC · 0 events', isPeak: false }
        ];
      }
      if (timeRange === 'Weeks') {
        return ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => ({
          name: day,
          eps: 0,
          display: `${day} · 0 events`,
          isPeak: false
        }));
      }
      return ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].map(m => ({
        name: m,
        eps: 0,
        display: `${m} · 0 events`,
        isPeak: false
      }));
    }

    if (timeRange === 'Days') {
      const buckets: Record<string, number> = {
        '00:00': 0,
        '04:00': 0,
        '08:00': 0,
        '12:00': 0,
        '16:00': 0,
        '20:00': 0,
        '23:59': 0
      };

      events.forEach(ev => {
        try {
          const d = new Date(ev.time);
          const h = d.getHours();
          if (h < 4) buckets['00:00']++;
          else if (h < 8) buckets['04:00']++;
          else if (h < 12) buckets['08:00']++;
          else if (h < 16) buckets['12:00']++;
          else if (h < 20) buckets['16:00']++;
          else if (h < 23) buckets['20:00']++;
          else buckets['23:59']++;
        } catch {
          buckets['12:00']++;
        }
      });

      const maxVal = Math.max(...Object.values(buckets), 1);
      return Object.entries(buckets).map(([name, count]) => ({
        name,
        eps: count,
        display: `${name} UTC · ${count} events`,
        isPeak: count === maxVal && count > 0
      }));
    }

    if (timeRange === 'Weeks') {
      const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const counts = [0, 0, 0, 0, 0, 0, 0];

      events.forEach(ev => {
        try {
          const d = new Date(ev.time);
          const dayIdx = d.getDay();
          if (!isNaN(dayIdx)) counts[dayIdx]++;
        } catch {
          counts[3]++;
        }
      });

      const maxVal = Math.max(...counts, 1);
      return days.map((day, idx) => ({
        name: day,
        eps: counts[idx],
        display: `${day} · ${counts[idx]} events`,
        isPeak: counts[idx] === maxVal && counts[idx] > 0
      }));
    }

    // Months View
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const monthCounts = new Array(12).fill(0);

    events.forEach(ev => {
      try {
        const d = new Date(ev.time);
        const m = d.getMonth();
        if (!isNaN(m) && m >= 0 && m < 12) monthCounts[m]++;
      } catch {
        monthCounts[8]++;
      }
    });

    const maxVal = Math.max(...monthCounts, 1);
    return months.map((m, idx) => ({
      name: m,
      eps: monthCounts[idx],
      display: `${m} · ${monthCounts[idx]} events`,
      isPeak: monthCounts[idx] === maxVal && monthCounts[idx] > 0
    }));
  }, [events, timeRange]);

  return (
    <div className="obsidian-card p-5 sm:p-6 space-y-4">
      {/* Header with Range Dropdown */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h4 className="text-sm font-bold text-white tracking-wide font-mono">
              Traffic Velocity & Ingestion Timeline
            </h4>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            {events.length > 0 
              ? `Real-time normalized event distribution (${timeRange.toLowerCase()} view · ${events.length} total events)`
              : 'Awaiting log ingestion — upload a file to plot live traffic velocity'}
          </p>
        </div>

        {/* Accessible Dropdown Menu */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setIsDropdownOpen(!isDropdownOpen)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-2xl bg-[#1d2138] hover:bg-[#252b47] text-xs font-semibold text-cyan-300 border border-cyan-500/30 hover:border-cyan-500/60 shadow-sm transition-all cursor-pointer"
            aria-expanded={isDropdownOpen}
            aria-haspopup="listbox"
          >
            <Calendar className="w-3.5 h-3.5 text-cyan-400" />
            <span>{timeRange}</span>
            <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${isDropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          {/* Dropdown Popover */}
          {isDropdownOpen && (
            <div className="absolute right-0 mt-2 w-44 rounded-2xl bg-[#131627] border border-slate-700 shadow-2xl shadow-black/80 py-1.5 z-30 animate-fade-in backdrop-blur-xl">
              {(['Days', 'Weeks', 'Months'] as TimeRangeOption[]).map((option) => (
                <button
                  key={option}
                  onClick={() => {
                    setTimeRange(option);
                    setIsDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3.5 py-2 text-xs font-medium transition-colors text-left ${
                    timeRange === option
                      ? 'bg-cyan-500/15 text-cyan-300 font-bold'
                      : 'text-slate-300 hover:bg-slate-800/70 hover:text-white'
                  }`}
                  role="option"
                  aria-selected={timeRange === option}
                >
                  <div className="flex items-center gap-2">
                    {option === 'Days' && <Clock className="w-3.5 h-3.5 text-purple-400" />}
                    {option === 'Weeks' && <Calendar className="w-3.5 h-3.5 text-cyan-400" />}
                    {option === 'Months' && <BarChart3 className="w-3.5 h-3.5 text-pink-400" />}
                    <span>{option} View</span>
                  </div>
                  {timeRange === option && <Check className="w-3.5 h-3.5 text-cyan-400" />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Smooth Wave Area Chart */}
      <div className="h-60 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={activeData} margin={{ top: 20, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="waveGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.85} />
                <stop offset="45%" stopColor="#2563eb" stopOpacity={0.5} />
                <stop offset="100%" stopColor="#1e3a8a" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1c2035" vertical={false} />
            <XAxis 
              dataKey="name" 
              stroke="#64748b" 
              fontSize={12} 
              tickLine={false}
              axisLine={false}
              tick={({ x, y, payload }) => {
                const isPeak = activeData.find(d => d.name === payload.value)?.isPeak;
                return (
                  <text 
                    x={x} 
                    y={y + 12} 
                    textAnchor="middle" 
                    fill={isPeak ? '#38bdf8' : '#94a3b8'}
                    fontWeight={isPeak ? 'bold' : 'normal'}
                    fontSize={11}
                  >
                    {payload.value}
                  </text>
                );
              }}
            />
            <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
            <Tooltip 
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="px-3.5 py-2 rounded-2xl bg-white text-slate-900 font-bold text-xs shadow-xl shadow-cyan-500/30 flex items-center gap-2 border border-slate-200">
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-600 animate-ping" />
                      <span>{payload[0].payload.display}</span>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area 
              type="natural" 
              dataKey="eps" 
              stroke="#38bdf8" 
              strokeWidth={3} 
              fillOpacity={1} 
              fill="url(#waveGradient)" 
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
};
