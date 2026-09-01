import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'deny' | 'allow' | 'critical' | 'high' | 'medium' | 'low' | 'network' | 'detection' | 'vendor' | 'uuid';
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  className = '',
  size = 'md'
}) => {
  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5'
  }[size];

  const variantClasses = {
    default: 'bg-slate-800/80 text-slate-300 border border-slate-700/60',
    deny: 'bg-rose-500/15 text-rose-300 border border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.15)] font-semibold',
    allow: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.15)] font-semibold',
    critical: 'bg-red-600/20 text-red-200 border border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.25)] font-bold animate-pulse',
    high: 'bg-orange-500/20 text-orange-300 border border-orange-500/40 font-semibold',
    medium: 'bg-amber-500/20 text-amber-300 border border-amber-500/40',
    low: 'bg-blue-500/20 text-blue-300 border border-blue-500/40',
    network: 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 font-medium',
    detection: 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-semibold',
    vendor: 'bg-slate-800 text-slate-300 border border-slate-700/80 hover:border-slate-500 transition-colors',
    uuid: 'font-mono text-[11px] bg-slate-900/90 text-cyan-400 border border-cyan-900/50'
  }[variant];

  return (
    <span className={`inline-flex items-center gap-1 rounded-md tracking-wide font-medium transition-all ${sizeClasses} ${variantClasses} ${className}`}>
      {children}
    </span>
  );
};
