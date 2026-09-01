import React from 'react';
import { Shield, Radio, Server, Terminal, ArrowUpRight } from 'lucide-react';
import { SummaryStats } from '../../types/events';

interface VendorProjectGridProps {
  stats: SummaryStats;
  onSelectVendor: (vendor: string) => void;
  selectedVendor: string;
}

export const VendorProjectGrid: React.FC<VendorProjectGridProps> = ({
  stats,
  onSelectVendor,
  selectedVendor
}) => {
  const vendors = [
    {
      id: 'Palo Alto Networks',
      name: 'Palo Alto Networks',
      product: 'PAN-OS Traffic (CSV)',
      icon: Shield,
      color: 'from-blue-500 to-cyan-500',
      barColor: 'bg-cyan-400',
      iconBg: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
      count: stats.vendorCounts['Palo Alto Networks'] || 3,
      total: 10,
    },
    {
      id: 'OISF',
      name: 'Suricata IDS / IPS',
      product: 'EVE JSON Telemetry',
      icon: Radio,
      color: 'from-purple-500 to-pink-500',
      barColor: 'bg-pink-400',
      iconBg: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
      count: stats.vendorCounts['OISF'] || stats.vendorCounts['OISF / Suricata'] || 3,
      total: 10,
    },
    {
      id: 'Fortinet',
      name: 'Fortinet FortiGate',
      product: 'FortiOS KV Stream',
      icon: Server,
      color: 'from-emerald-500 to-teal-500',
      barColor: 'bg-emerald-400',
      iconBg: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
      count: stats.vendorCounts['Fortinet'] || 2,
      total: 10,
    },
    {
      id: 'Cisco',
      name: 'Cisco ASA Security',
      product: 'Perimeter Syslog %ASA',
      icon: Terminal,
      color: 'from-amber-500 to-orange-500',
      barColor: 'bg-amber-400',
      iconBg: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
      count: stats.vendorCounts['Cisco'] || 2,
      total: 10,
    }
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
          Perimeter Device Sources
        </h4>
        <span className="text-xs text-cyan-400 font-mono">
          {Object.keys(stats.vendorCounts).length} Active Configs
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
        {vendors.map((v) => {
          const isSelected = selectedVendor === v.id || selectedVendor === v.name;
          const Icon = v.icon;
          const pct = Math.min(100, Math.round((v.count / v.total) * 100));

          return (
            <div
              key={v.id}
              onClick={() => onSelectVendor(isSelected ? 'ALL' : v.id)}
              className={`p-4 sm:p-5 rounded-3xl border transition-all duration-200 cursor-pointer ${
                isSelected
                  ? 'bg-[#1b1f36] border-cyan-400 shadow-glow-cyan ring-1 ring-cyan-400/50'
                  : 'bg-[#141726] hover:bg-[#1a1e32] border-white/5 hover:border-white/15'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className={`p-2.5 rounded-2xl ${v.iconBg}`}>
                  <Icon className="w-4 h-4" />
                </div>
                
                {/* Vendor Avatar Stack */}
                <div className="flex -space-x-1.5 overflow-hidden">
                  <div className="inline-block h-6 w-6 rounded-full bg-slate-800 border-2 border-[#141726] text-[9px] font-bold text-center leading-5 text-cyan-300">
                    FW
                  </div>
                  <div className="inline-block h-6 w-6 rounded-full bg-slate-700 border-2 border-[#141726] text-[9px] font-bold text-center leading-5 text-purple-300">
                    OC
                  </div>
                </div>
              </div>

              <h5 className="text-sm font-bold text-slate-100 font-mono truncate">
                {v.name}
              </h5>
              <p className="text-xs text-slate-400 truncate mb-3">
                {v.product}
              </p>

              {/* Progress Bar & Counter */}
              <div className="space-y-1.5">
                <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${v.barColor} transition-all duration-500`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] font-mono text-slate-400">
                  <span>{pct}% load</span>
                  <span className="text-slate-200 font-semibold">{v.count} events</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
