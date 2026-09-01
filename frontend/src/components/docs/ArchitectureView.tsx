import React, { useState } from 'react';
import { FileCode, Layers, ShieldCheck, Cpu, Database, Server, CheckCircle2, Box, Copy, Check } from 'lucide-react';
import { VENDOR_YAML_CONFIGS } from '../../data/yamlConfigs';

export const ArchitectureView: React.FC = () => {
  const [selectedConfigId, setSelectedConfigId] = useState<string>(VENDOR_YAML_CONFIGS[0].id);
  const [copied, setCopied] = useState(false);

  const selectedConfig = VENDOR_YAML_CONFIGS.find(c => c.id === selectedConfigId) || VENDOR_YAML_CONFIGS[0];

  const handleCopyYaml = () => {
    navigator.clipboard.writeText(selectedConfig.yamlContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Top Architecture Overview Banner */}
      <div className="bg-slate-900/80 rounded-2xl p-6 border border-slate-800 backdrop-blur-md shadow-lg space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white font-mono">
              LogFusion Architecture & OCSF Normalization Pipeline
            </h2>
            <p className="text-xs text-slate-400">
              LogFusion (ULPF) · Open Cybersecurity Schema Framework (OCSF v1.1.0)
            </p>
          </div>
        </div>

        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Rather than inventing a proprietary taxonomy, <strong>LogFusion</strong> adopts the <strong>Open Cybersecurity Schema Framework (OCSF)</strong> under the Linux Foundation. Enterprises ingest raw logs from perimeter firewalls, IDS/IPS, VPN gateways, and WAFs — converting them into standardized, lossless, analytics-ready JSON while guaranteeing full forensic traceability.
        </p>

        {/* 6 Core Pipeline Stages */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-3">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 1</span>
            <h4 className="text-xs font-bold text-slate-200">Ingest</h4>
            <p className="text-[10px] text-slate-400">CSV, KV, JSON, Syslog stream</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 2</span>
            <h4 className="text-xs font-bold text-slate-200">Detect</h4>
            <p className="text-[10px] text-slate-400">Match YAML vendor mapping</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 3</span>
            <h4 className="text-xs font-bold text-slate-200">Parse</h4>
            <p className="text-[10px] text-slate-400">Extract raw fields & values</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 4</span>
            <h4 className="text-xs font-bold text-slate-200">Classify</h4>
            <p className="text-[10px] text-slate-400">Assign OCSF Class (4001/2004)</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 5</span>
            <h4 className="text-xs font-bold text-slate-200">Map & Transform</h4>
            <p className="text-[10px] text-slate-400">Translate to nested OCSF paths</p>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
            <span className="text-[10px] font-mono text-cyan-400 font-bold">STAGE 6</span>
            <h4 className="text-xs font-bold text-slate-200">Preserve & Store</h4>
            <p className="text-[10px] text-slate-400">UUID stamp + unmapped bucket</p>
          </div>
        </div>
      </div>

      {/* Plug and Play YAML Mapping Config Explorer */}
      <div className="bg-slate-900/80 rounded-2xl p-6 border border-slate-800 backdrop-blur-md shadow-lg space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <FileCode className="w-5 h-5 text-purple-400" />
              <h3 className="text-base font-bold text-white font-mono">
                Plug-and-Play YAML Mapping Config Library
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Onboard new perimeter vendors simply by dropping a YAML file into the config folder — zero code changes required.
            </p>
          </div>

          <button
            onClick={handleCopyYaml}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 transition-colors self-start sm:self-auto"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied YAML' : 'Copy Config YAML'}</span>
          </button>
        </div>

        {/* Vendor Selector Tabs */}
        <div className="flex flex-wrap gap-2">
          {VENDOR_YAML_CONFIGS.map(config => (
            <button
              key={config.id}
              onClick={() => setSelectedConfigId(config.id)}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono transition-all ${
                selectedConfigId === config.id
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-md font-semibold'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                {config.format.toUpperCase()}
              </span>
              <span>{config.vendor}</span>
            </button>
          ))}
        </div>

        {/* YAML Viewer */}
        <div className="space-y-2">
          <p className="text-xs text-slate-400 italic">
            {selectedConfig.description}
          </p>
          <pre className="p-4 rounded-xl bg-slate-950 border border-purple-900/40 text-purple-200/90 font-mono text-xs overflow-x-auto leading-relaxed shadow-inner max-h-[420px] overflow-y-auto">
            {selectedConfig.yamlContent}
          </pre>
        </div>
      </div>

      {/* Deliverable Matrix */}
      <div className="bg-slate-900/80 rounded-2xl p-6 border border-slate-800 backdrop-blur-md shadow-lg space-y-4">
        <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
          <Box className="w-5 h-5 text-cyan-400" />
          ULPF Deliverable Satisfaction Matrix
        </h3>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3.5">Feature</th>
                <th className="py-2.5 px-3.5">What it does</th>
                <th className="py-2.5 px-3.5">Deliverable Satisfied</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">Multi-format Ingestion</td>
                <td className="py-2.5 px-3.5 text-slate-400">Accepts CSV, KV syslog, JSON, plain syslog text, XML</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Universal Ingestion</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">Vendor Auto-Detection</td>
                <td className="py-2.5 px-3.5 text-slate-400">Matches incoming events to YAML mapping configs automatically</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Plug-and-play onboarding (e)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">OCSF Normalization</td>
                <td className="py-2.5 px-3.5 text-slate-400">Maps vendor fields into shared nested OCSF schema</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Common taxonomy (c)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">Raw Preservation + UUID</td>
                <td className="py-2.5 px-3.5 text-slate-400">Untouched original event linked to normalized form by shared UUID</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Losslessness + traceability (a, d)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">Unmapped Field Bucketing</td>
                <td className="py-2.5 px-3.5 text-slate-400">Vendor-specific fields with no OCSF home kept in unmapped dictionary</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Source-specific extraction (b)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">Unified Dashboard</td>
                <td className="py-2.5 px-3.5 text-slate-400">One consistent view across all vendors with class/vendor filters</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">Unified visibility (f)</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3.5 font-bold text-cyan-300">RAG Chatbot Panel</td>
                <td className="py-2.5 px-3.5 text-slate-400">Answers questions grounded in the normalized event store</td>
                <td className="py-2.5 px-3.5 text-emerald-400 font-semibold">AI/ML-ready analytics (h)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
