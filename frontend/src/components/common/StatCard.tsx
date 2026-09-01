import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: string;
  trendPositive?: boolean;
  icon: LucideIcon;
  color?: 'cyan' | 'rose' | 'emerald' | 'amber' | 'purple' | 'blue';
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  trend,
  trendPositive,
  icon: Icon,
  color = 'cyan',
  onClick
}) => {
  const colorMap = {
    cyan: {
      bg: 'from-cyan-500/10 to-transparent',
      border: 'border-cyan-500/30 hover:border-cyan-500/60',
      iconBg: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]',
      val: 'text-cyan-100'
    },
    rose: {
      bg: 'from-rose-500/10 to-transparent',
      border: 'border-rose-500/30 hover:border-rose-500/60',
      iconBg: 'bg-rose-500/15 text-rose-400 border border-rose-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]',
      val: 'text-rose-100'
    },
    emerald: {
      bg: 'from-emerald-500/10 to-transparent',
      border: 'border-emerald-500/30 hover:border-emerald-500/60',
      iconBg: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]',
      val: 'text-emerald-100'
    },
    amber: {
      bg: 'from-amber-500/10 to-transparent',
      border: 'border-amber-500/30 hover:border-amber-500/60',
      iconBg: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      val: 'text-amber-100'
    },
    purple: {
      bg: 'from-purple-500/10 to-transparent',
      border: 'border-purple-500/30 hover:border-purple-500/60',
      iconBg: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(168,85,247,0.15)]',
      val: 'text-purple-100'
    },
    blue: {
      bg: 'from-blue-500/10 to-transparent',
      border: 'border-blue-500/30 hover:border-blue-500/60',
      iconBg: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
      glow: 'group-hover:shadow-[0_0_20px_rgba(59,130,246,0.15)]',
      val: 'text-blue-100'
    }
  }[color];

  return (
    <div
      onClick={onClick}
      className={`group relative overflow-hidden rounded-xl bg-slate-900/80 bg-gradient-to-br ${colorMap.bg} p-4 sm:p-5 border ${colorMap.border} ${colorMap.glow} transition-all duration-300 backdrop-blur-md cursor-pointer hover:-translate-y-0.5`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <h3 className={`text-2xl sm:text-3xl font-bold font-mono tracking-tight ${colorMap.val}`}>
              {value}
            </h3>
            {trend && (
              <span className={`text-xs font-medium ${trendPositive ? 'text-emerald-400' : 'text-rose-400'}`}>
                {trend}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="mt-1 text-xs text-slate-400 font-normal">{subtitle}</p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg ${colorMap.iconBg} transition-transform group-hover:scale-110`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-slate-700 to-transparent group-hover:via-cyan-400 transition-all" />
    </div>
  );
};
