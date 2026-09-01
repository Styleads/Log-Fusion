import React from 'react';
import { Database, Radio, Ban, CheckCircle, AlertTriangle } from 'lucide-react';
import { SummaryStats } from '../../types/events';

interface StatCardsGridProps {
  stats: SummaryStats;
  onFilterClick?: (filterType: string, value: string) => void;
}

export const StatCardsGrid: React.FC<StatCardsGridProps> = ({ stats, onFilterClick }) => {
  const denyPercent = stats.totalEvents > 0 ? Math.round((stats.denyCount / stats.totalEvents) * 100) : 68;

  const items = [
    {
      title: 'Total Ingested',
      val: stats.totalEvents,
      sub: '100% Lossless',
      icon: Database,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/15 border-cyan-500/30',
      filter: () => onFilterClick?.('reset', 'ALL')
    },
    {
      title: 'Active Sources',
      val: stats.activeSources,
      sub: '4 Vendors',
      icon: Radio,
      color: 'text-purple-400',
      bg: 'bg-purple-500/15 border-purple-500/30',
      filter: () => onFilterClick?.('vendor', 'ALL')
    },
    {
      title: 'Blocked / Deny',
      val: stats.denyCount,
      sub: `${denyPercent}% of traffic`,
      icon: Ban,
      color: 'text-pink-400',
      bg: 'bg-pink-500/15 border-pink-500/30',
      filter: () => onFilterClick?.('action', 'Deny')
    },
    {
      title: 'Allowed / Pass',
      val: stats.allowCount,
      sub: 'Normal Flow',
      icon: CheckCircle,
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/15 border-emerald-500/30',
      filter: () => onFilterClick?.('action', 'Allow')
    },
    {
      title: 'Findings',
      val: stats.activeFindings,
      sub: 'Threat Alerts',
      icon: AlertTriangle,
      color: 'text-amber-400',
      bg: 'bg-amber-500/15 border-amber-500/30',
      filter: () => onFilterClick?.('class', 'Detection Finding')
    }
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
      {items.map((item, idx) => {
        const Icon = item.icon;
        return (
          <div
            key={idx}
            onClick={item.filter}
            className="obsidian-card-interactive p-4 rounded-3xl cursor-pointer flex flex-col justify-between"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                {item.title}
              </span>
              <div className={`p-2 rounded-2xl border ${item.bg} ${item.color}`}>
                <Icon className="w-3.5 h-3.5" />
              </div>
            </div>

            <div>
              <h3 className="text-2xl font-bold font-mono text-white tracking-tight">
                {item.val}
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5 font-sans">
                {item.sub}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
};
