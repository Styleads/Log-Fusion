import React, { useMemo } from 'react';
import { Shield, Radio, Server, Terminal, Globe, Layers } from 'lucide-react';
import { SummaryStats } from '../../types/events';
import { OCSFEvent } from '../../types/ocsf';

interface VendorProjectGridProps {
  stats: SummaryStats;
  events?: OCSFEvent[];
  onSelectVendor: (vendor: string) => void;
  selectedVendor: string;
}

interface VendorProfile {
  id: string;
  name: string;
  product: string;
  icon: React.ComponentType<{ className?: string }>;
  barColor: string;
  iconBg: string;
  avatar: string;
}

const KNOWN_PROFILES: Record<string, Omit<VendorProfile, 'id'>> = {
  squid: {
    name: 'Squid Proxy',
    product: 'Native Access Telemetry',
    icon: Globe,
    barColor: 'bg-emerald-400',
    iconBg: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    avatar: 'SQ',
  },
  'palo alto': {
    name: 'Palo Alto Networks',
    product: 'PAN-OS Traffic (CSV)',
    icon: Shield,
    barColor: 'bg-cyan-400',
    iconBg: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
    avatar: 'PA',
  },
  microsoft: {
    name: 'Microsoft Windows',
    product: 'Windows Firewall (pfirewall.log)',
    icon: Shield,
    barColor: 'bg-sky-400',
    iconBg: 'bg-sky-500/15 text-sky-400 border border-sky-500/30',
    avatar: 'MS',
  },
  suricata: {
    name: 'Suricata IDS / IPS',
    product: 'EVE JSON Telemetry',
    icon: Radio,
    barColor: 'bg-pink-400',
    iconBg: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
    avatar: 'SU',
  },
  oisf: {
    name: 'Suricata IDS / IPS',
    product: 'EVE JSON Telemetry',
    icon: Radio,
    barColor: 'bg-pink-400',
    iconBg: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
    avatar: 'SU',
  },
  fortinet: {
    name: 'Fortinet FortiGate',
    product: 'FortiOS KV Stream',
    icon: Server,
    barColor: 'bg-amber-400',
    iconBg: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    avatar: 'FT',
  },
  cisco: {
    name: 'Cisco ASA Security',
    product: 'Perimeter Syslog %ASA',
    icon: Terminal,
    barColor: 'bg-orange-400',
    iconBg: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    avatar: 'CS',
  },
};

function resolveProfile(vName: string, sampleEvent?: OCSFEvent): VendorProfile {
  const lower = vName.toLowerCase();
  for (const [key, prof] of Object.entries(KNOWN_PROFILES)) {
    if (lower.includes(key)) {
      return {
        id: vName,
        name: prof.name,
        product: (sampleEvent as any)?.metadata?.product?.name || sampleEvent?.source_product || prof.product,
        icon: prof.icon,
        barColor: prof.barColor,
        iconBg: prof.iconBg,
        avatar: prof.avatar,
      };
    }
  }

  // Dynamic fallback for any other custom or auto-mapped vendor
  const initials = vName.replace(/[^a-zA-Z0-9]/g, '').slice(0, 2).toUpperCase() || 'TX';
  return {
    id: vName,
    name: vName,
    product: (sampleEvent as any)?.metadata?.product?.name || sampleEvent?.source_product || sampleEvent?.device?.type || 'Security Telemetry',
    icon: Layers,
    barColor: 'bg-indigo-400',
    iconBg: 'bg-indigo-500/15 text-indigo-400 border border-indigo-500/30',
    avatar: initials,
  };
}

export const VendorProjectGrid: React.FC<VendorProjectGridProps> = ({
  stats,
  events = [],
  onSelectVendor,
  selectedVendor,
}) => {
  const vendorCards = useMemo(() => {
    // 1. Gather all active vendors from actual dataset
    const activeVendorNames = Object.keys(stats.vendorCounts).filter((k) => k && k !== 'Other');

    // 2. Standard baseline perimeter sources
    const defaultPerimeterVendors = [
      'Squid',
      'Palo Alto Networks',
      'Suricata',
      'Fortinet',
      'Cisco',
    ];

    // Combine all unique vendor keys, with active sources taking precedence
    const allVendorKeys = Array.from(new Set([...activeVendorNames, ...defaultPerimeterVendors]));

    const cards = allVendorKeys.map((key) => {
      // Find sample event if available
      const sample = events.find((e) => {
        const evVendor = e.device?.vendor_name || e.source_vendor || '';
        return evVendor.toLowerCase() === key.toLowerCase() || evVendor.toLowerCase().includes(key.toLowerCase());
      });

      // Strict count from actual database stats
      let count = stats.vendorCounts[key] || 0;
      if (count === 0) {
        for (const [vKey, val] of Object.entries(stats.vendorCounts)) {
          if (vKey.toLowerCase() === key.toLowerCase() || vKey.toLowerCase().includes(key.toLowerCase())) {
            count = val;
            break;
          }
        }
      }

      const prof = resolveProfile(key, sample);
      const pct = stats.totalEvents > 0 ? Math.min(100, Math.round((count / stats.totalEvents) * 100)) : 0;

      return {
        ...prof,
        count,
        pct,
      };
    });

    // Sort: vendors with actual events first (highest event count first)
    return cards.sort((a, b) => b.count - a.count);
  }, [stats, events]);

  const activeCount = Object.keys(stats.vendorCounts).filter(k => (stats.vendorCounts[k] || 0) > 0).length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
          Perimeter Device Sources
        </h4>
        <span className="text-xs text-cyan-400 font-mono">
          {activeCount} Active Source{activeCount === 1 ? '' : 's'} · {stats.totalEvents} Total Events
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {vendorCards.map((v) => {
          const isSelected = selectedVendor === v.id || selectedVendor === v.name;
          const Icon = v.icon;

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
                    {v.avatar}
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
                    style={{ width: `${v.pct}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] font-mono text-slate-400">
                  <span>{v.pct}% volume</span>
                  <span className={`${v.count > 0 ? 'text-cyan-300 font-bold' : 'text-slate-500'}`}>
                    {v.count} event{v.count === 1 ? '' : 's'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
