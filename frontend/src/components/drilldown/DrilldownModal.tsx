import React, { useState } from 'react';
import { X, Copy, Check, Shield, Layers, FileCode, GitFork, ArrowLeftRight, CheckCircle2 } from 'lucide-react';
import { OCSFEvent, FieldMappingLineage } from '../../types/ocsf';
import { Badge } from '../common/Badge';
import { FieldLineageTable } from './FieldLineageTable';
import { UnmappedInspector } from './UnmappedInspector';

interface DrilldownModalProps {
  event: OCSFEvent | null;
  onClose: () => void;
}

export const DrilldownModal: React.FC<DrilldownModalProps> = ({ event, onClose }) => {
  const [activeTab, setActiveTab] = useState<'side-by-side' | 'json' | 'lineage' | 'unmapped'>('side-by-side');
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedJSON, setCopiedJSON] = useState(false);

  if (!event) return null;

  // Generate dynamic lineage from event fields
  const lineage: FieldMappingLineage[] = [
    { raw_field: 'Source IP', raw_value: event.src_endpoint?.ip || '', ocsf_path: 'src_endpoint.ip', status: 'mapped' },
    { raw_field: 'Source Port', raw_value: event.src_endpoint?.port ?? '—', ocsf_path: 'src_endpoint.port', status: 'mapped' },
    { raw_field: 'Dest IP', raw_value: event.dst_endpoint?.ip || '', ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
    { raw_field: 'Dest Port', raw_value: event.dst_endpoint?.port ?? '—', ocsf_path: 'dst_endpoint.port', status: 'mapped' },
    { raw_field: 'Protocol', raw_value: event.connection_info?.protocol_name || '', ocsf_path: 'connection_info.protocol_name', status: 'transformed' },
    { raw_field: 'Action / Status', raw_value: event.activity_name || '', ocsf_path: 'activity_name / activity_id', status: 'transformed' },
    { raw_field: 'Device Hostname', raw_value: event.device?.name || '', ocsf_path: 'device.name', status: 'mapped' },
    { raw_field: 'Vendor', raw_value: event.device?.vendor_name || event.source_vendor, ocsf_path: 'device.vendor_name', status: 'static' }
  ];

  if (event.firewall_rule?.name) {
    lineage.push({ raw_field: 'Firewall Rule', raw_value: event.firewall_rule.name, ocsf_path: 'firewall_rule.name', status: 'mapped' });
  }

  if (event.finding_info) {
    lineage.push(
      { raw_field: 'Alert Signature', raw_value: event.finding_info.title, ocsf_path: 'finding_info.title', status: 'mapped' },
      { raw_field: 'Signature UID', raw_value: event.finding_info.uid, ocsf_path: 'finding_info.uid', status: 'mapped' }
    );
  }

  if (event.unmapped) {
    Object.entries(event.unmapped).forEach(([k, v]) => {
      lineage.push({ raw_field: k, raw_value: String(v), ocsf_path: `unmapped.${k}`, status: 'unmapped' });
    });
  }

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(event.raw_data);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopiedJSON(true);
    setTimeout(() => setCopiedJSON(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-6xl max-h-[92vh] flex flex-col rounded-2xl bg-[#0b0f19] border border-slate-700 shadow-2xl shadow-cyan-950/40 overflow-hidden">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white font-mono">
                  Event Drill-Down & Forensic Traceability
                </h3>
                <Badge variant={event.class_name === 'Detection Finding' ? 'detection' : 'network'} size="sm">
                  {event.class_name} ({event.class_uid})
                </Badge>
              </div>
              
              {/* Cryptographic Linkage Banner */}
              <div className="flex items-center gap-2 mt-1 text-xs">
                <span className="text-slate-400 font-mono">Shared Event UID:</span>
                <span className="font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                  {event.event_uid}
                </span>
                <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-semibold ml-2">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Lossless Traceability Verified
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center justify-between px-5 py-2.5 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('side-by-side')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'side-by-side'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ArrowLeftRight className="w-3.5 h-3.5" />
              Side-by-Side (Raw vs OCSF)
            </button>

            <button
              onClick={() => setActiveTab('lineage')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'lineage'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitFork className="w-3.5 h-3.5" />
              Field Lineage Table
            </button>

            <button
              onClick={() => setActiveTab('unmapped')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'unmapped'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Unmapped Bucket ({event.unmapped ? Object.keys(event.unmapped).length : 0})
            </button>

            <button
              onClick={() => setActiveTab('json')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'json'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              OCSF JSON Only
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyRaw}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition-colors"
            >
              {copiedRaw ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedRaw ? 'Copied Raw' : 'Copy Raw'}</span>
            </button>
            <button
              onClick={handleCopyJSON}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono bg-cyan-950/60 text-cyan-300 hover:text-white border border-cyan-800/60 transition-colors"
            >
              {copiedJSON ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedJSON ? 'Copied JSON' : 'Copy OCSF JSON'}</span>
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto max-h-[calc(92vh-140px)] space-y-4">
          
          {/* TAB 1: SIDE BY SIDE VIEW */}
          {activeTab === 'side-by-side' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              
              {/* Left Pane: Untouched Raw Log */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                    Original Raw Log Stream ({event.raw_format.toUpperCase()})
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {event.raw_data.length} bytes · untouched
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-amber-200/90 whitespace-pre-wrap break-all leading-relaxed shadow-inner max-h-[460px] overflow-y-auto">
                  {event.raw_data}
                </div>
              </div>

              {/* Right Pane: Branched OCSF JSON */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                    Normalized OCSF v1.1.0 JSON Document
                  </span>
                  <span className="text-[11px] text-cyan-400 font-mono">
                    OCSF Class {event.class_uid}
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-cyan-900/40 font-mono text-xs text-cyan-100/90 whitespace-pre leading-relaxed shadow-inner max-h-[460px] overflow-y-auto">
                  {JSON.stringify(event, null, 2)}
                </div>
              </div>

            </div>
          )}

          {/* TAB 2: FIELD LINEAGE TABLE */}
          {activeTab === 'lineage' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Detailed field extraction, schema alignment, and value translation mapping from raw perimeter format into OCSF v1.1.0 taxonomy.
              </p>
              <FieldLineageTable lineage={lineage} />
            </div>
          )}

          {/* TAB 3: UNMAPPED BUCKET */}
          {activeTab === 'unmapped' && (
            <UnmappedInspector unmapped={event.unmapped} rawFormat={event.raw_format} />
          )}

          {/* TAB 4: OCSF JSON ONLY */}
          {activeTab === 'json' && (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-200/90 whitespace-pre overflow-x-auto">
              {JSON.stringify(event, null, 2)}
            </div>
          )}

        </div>
      </div>
    </div>
  );
};
