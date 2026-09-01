import React, { useState, useRef, useEffect } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer 
} from 'recharts';
import { OCSFEvent } from '../../types/ocsf';
import { ChevronDown, Check, Calendar, Clock, BarChart3 } from 'lucide-react';

interface VisualAnalyticsProps {
  events: OCSFEvent[];
}

type TimeRangeOption = 'Weeks' | 'Days' | 'Months';

export const VisualAnalytics: React.FC<VisualAnalyticsProps> = ({ events }) => {
  const [timeRange, setTimeRange] = useState<TimeRangeOption>('Weeks');
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

  // Dynamic datasets depending on selected range
  const datasets: Record<TimeRangeOption, Array<{ name: string; eps: number; display: string; isPeak?: boolean }>> = {
    Weeks: [
      { name: 'Sun', eps: 2.1, display: '2h 10m · 2.1k events' },
      { name: 'Mon', eps: 4.8, display: '4h 45m · 4.8k events' },
      { name: 'Tue', eps: 3.2, display: '3h 15m · 3.2k events' },
      { name: 'Wed', eps: 6.9, display: '2h 45min (Peak Traffic)', isPeak: true },
      { name: 'Thu', eps: 5.1, display: '5h 05m · 5.1k events' },
      { name: 'Fri', eps: 7.4, display: '7h 20m · 7.4k events' },
      { name: 'Sat', eps: 3.8, display: '3h 40m · 3.8k events' }
    ],
    Days: [
      { name: '00:00', eps: 1.2, display: '00:00 UTC · 1.2k events' },
      { name: '04:00', eps: 0.8, display: '04:00 UTC · 800 events' },
      { name: '08:00', eps: 3.9, display: '08:00 UTC · 3.9k events' },
      { name: '12:00', eps: 6.4, display: '12:00 UTC · 6.4k events', isPeak: true },
      { name: '16:00', eps: 5.2, display: '16:00 UTC · 5.2k events' },
      { name: '20:00', eps: 4.1, display: '20:00 UTC · 4.1k events' },
      { name: '23:59', eps: 2.5, display: '23:59 UTC · 2.5k events' }
    ],
    Months: [
      { name: 'Jan', eps: 32.4, display: 'Jan · 32.4k events' },
      { name: 'Feb', eps: 41.8, display: 'Feb · 41.8k events' },
      { name: 'Mar', eps: 38.2, display: 'Mar · 38.2k events' },
      { name: 'Apr', eps: 54.9, display: 'Apr · 54.9k events' },
      { name: 'May', eps: 61.1, display: 'May · 61.1k events' },
      { name: 'Jun', eps: 78.4, display: 'Jun · 78.4k events (Highest)', isPeak: true },
      { name: 'Jul', eps: 69.8, display: 'Jul · 69.8k events' },
      { name: 'Aug', eps: 72.3, display: 'Aug · 72.3k events' }
    ]
  };

  const activeData = datasets[timeRange];

  return (
    <div className="obsidian-card p-5 sm:p-6 space-y-4">
      {/* Header with Range Dropdown */}
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-bold text-white tracking-wide font-mono">
            Traffic Velocity & Activity
          </h4>
          <p className="text-xs text-slate-400">
            Perimeter event normalization rate ({timeRange.toLowerCase()} view)
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
              {(['Weeks', 'Days', 'Months'] as TimeRangeOption[]).map((option) => (
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
                    {option === 'Weeks' && <Calendar className="w-3.5 h-3.5 text-cyan-400" />}
                    {option === 'Days' && <Clock className="w-3.5 h-3.5 text-purple-400" />}
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
