import React from 'react';
import { Layers, CheckCircle, Info } from 'lucide-react';

interface UnmappedInspectorProps {
  unmapped?: Record<string, any>;
  rawFormat: string;
}

export const UnmappedInspector: React.FC<UnmappedInspectorProps> = ({ unmapped, rawFormat }) => {
  const entries = unmapped ? Object.entries(unmapped) : [];

  return (
    <div className="space-y-4">
      {/* Explanation Banner */}
      <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200/90 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="font-semibold text-amber-300">Lossless Unmapped Bucketing Policy</p>
          <p className="mt-0.5 text-amber-200/80">
            Per the ULPF core specification, proprietary vendor attributes that do not map to standardized OCSF fields are preserved in the <code className="bg-amber-950/60 px-1 py-0.5 rounded text-amber-300 font-mono">unmapped</code> dictionary rather than being discarded.
          </p>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400 text-xs">
          <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
          <p className="font-medium text-slate-300">100% of vendor attributes mapped to native OCSF schema paths</p>
          <p className="text-slate-500 mt-1">No residual unmapped fields needed for this event</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950 shadow-inner">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3.5">Vendor Attribute Key</th>
                <th className="py-2.5 px-3.5">Preserved Value</th>
                <th className="py-2.5 px-3.5">Type</th>
                <th className="py-2.5 px-3.5">JSON Path</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {entries.map(([key, val]) => (
                <tr key={key} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-2.5 px-3.5 font-semibold text-amber-300">{key}</td>
                  <td className="py-2.5 px-3.5 text-slate-200">
                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                  </td>
                  <td className="py-2.5 px-3.5 text-slate-500 text-[11px]">{typeof val}</td>
                  <td className="py-2.5 px-3.5 text-cyan-400 font-mono text-[11px]">
                    unmapped.{key}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
