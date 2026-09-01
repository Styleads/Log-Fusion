import React from 'react';
import { ArrowRight, CheckCircle2, AlertTriangle, Layers, Shuffle } from 'lucide-react';
import { FieldMappingLineage } from '../../types/ocsf';

interface FieldLineageTableProps {
  lineage: FieldMappingLineage[];
}

export const FieldLineageTable: React.FC<FieldLineageTableProps> = ({ lineage }) => {
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/90 shadow-inner">
      <table className="w-full text-left text-xs font-mono">
        <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
          <tr>
            <th className="py-2.5 px-3.5">Raw Source Field</th>
            <th className="py-2.5 px-3.5">Extracted Value</th>
            <th className="py-2.5 px-3.5 text-center">Mapping</th>
            <th className="py-2.5 px-3.5">Normalized OCSF Path</th>
            <th className="py-2.5 px-3.5">Transform / Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 text-slate-300">
          {lineage.map((item, idx) => (
            <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
              {/* Raw field name */}
              <td className="py-2 px-3.5 whitespace-nowrap font-medium text-slate-400">
                {item.raw_field}
              </td>

              {/* Extracted value */}
              <td className="py-2 px-3.5 font-semibold text-cyan-300 max-w-[220px] truncate">
                {String(item.raw_value ?? '—')}
              </td>

              {/* Mapping arrow */}
              <td className="py-2 px-3.5 text-center text-slate-600">
                <ArrowRight className="w-3.5 h-3.5 mx-auto text-cyan-500/70" />
              </td>

              {/* OCSF Target Path */}
              <td className="py-2 px-3.5 whitespace-nowrap font-medium text-purple-300 bg-purple-950/10">
                {item.ocsf_path}
              </td>

              {/* Transform / Status */}
              <td className="py-2 px-3.5 whitespace-nowrap">
                {item.status === 'transformed' ? (
                  <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-800/40">
                    <Shuffle className="w-3 h-3" />
                    {item.transformation || 'transformed'}
                  </span>
                ) : item.status === 'unmapped' ? (
                  <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    <Layers className="w-3 h-3 text-amber-400" />
                    unmapped bucket
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-300 border border-emerald-800/40">
                    <CheckCircle2 className="w-3 h-3" />
                    direct map
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
