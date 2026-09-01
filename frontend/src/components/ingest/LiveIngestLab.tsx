import React, { useState } from 'react';
import { Play, Sparkles, Terminal, FileCode, CheckCircle2, ArrowRight, Layers, Eye, RefreshCw } from 'lucide-react';
import { SAMPLE_RAW_LOGS, SampleLogItem } from '../../data/sampleRawLogs';
import { processRawLog } from '../../services/ocsfEngine';
import { NormalizationPipelineOutput } from '../../types/events';
import { OCSFEvent } from '../../types/ocsf';
import { PipelineStepper } from './PipelineStepper';
import { FieldLineageTable } from '../drilldown/FieldLineageTable';
import { Badge } from '../common/Badge';

interface LiveIngestLabProps {
  onEventIngested: (event: OCSFEvent) => void;
  onOpenDrilldown: (event: OCSFEvent) => void;
}

export const LiveIngestLab: React.FC<LiveIngestLabProps> = ({ onEventIngested, onOpenDrilldown }) => {
  const [selectedSample, setSelectedSample] = useState<SampleLogItem>(SAMPLE_RAW_LOGS[0]);
  const [rawInput, setRawInput] = useState<string>(SAMPLE_RAW_LOGS[0].raw);
  const [pipelineOutput, setPipelineOutput] = useState<NormalizationPipelineOutput | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [recentlyAdded, setRecentlyAdded] = useState(false);

  const handleSelectSample = (sample: SampleLogItem) => {
    setSelectedSample(sample);
    setRawInput(sample.raw);
    setPipelineOutput(null);
    setRecentlyAdded(false);
  };

  const handleRunPipeline = async () => {
    setIsProcessing(true);
    setRecentlyAdded(false);

    // Short animation delay to illustrate stages
    setTimeout(() => {
      const output = processRawLog(rawInput);
      setPipelineOutput(output);
      setIsProcessing(false);
    }, 350);
  };

  const handleAddToLiveFeed = () => {
    if (pipelineOutput?.normalizedEvent) {
      onEventIngested(pipelineOutput.normalizedEvent);
      setRecentlyAdded(true);
      setTimeout(() => setRecentlyAdded(false), 3000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 backdrop-blur-md shadow-md">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white font-mono">
                Interactive Ingestion & Normalization Lab
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Test perimeter device raw logs across Palo Alto CSV, Suricata EVE JSON, Fortinet KV, and Cisco Syslog. Watch the YAML-driven engine auto-detect, parse, classify, map, and preserve in real-time.
            </p>
          </div>

          <button
            onClick={handleRunPipeline}
            disabled={isProcessing || !rawInput.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-xs tracking-wide bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-white shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isProcessing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Normalization Pipeline</span>
              </>
            )}
          </button>
        </div>

        {/* Sample Payload Selector Buttons */}
        <div className="mt-5 pt-4 border-t border-slate-800">
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono block mb-2">
            Load Pre-configured Perimeter Vendor Sample:
          </label>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_RAW_LOGS.map(sample => (
              <button
                key={sample.id}
                onClick={() => handleSelectSample(sample)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                  selectedSample.id === sample.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm font-semibold'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                  {sample.format.toUpperCase()}
                </span>
                <span>{sample.name}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Raw Input Editor Pane */}
      <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 backdrop-blur-md shadow-md space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Raw Log Payload (Input Stream)
            </h4>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            {rawInput.length} characters
          </span>
        </div>

        <textarea
          rows={4}
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          placeholder="Paste raw syslog, CSV, JSON, or KV string from any perimeter device..."
          className="w-full p-3.5 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-amber-200/90 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 leading-relaxed shadow-inner"
        />
      </div>

      {/* Pipeline Telemetry & Results */}
      {pipelineOutput && (
        <div className="space-y-6 animate-slide-up">
          {/* Stepper */}
          <PipelineStepper stages={pipelineOutput.stages} />

          {/* Result Breakdown Card */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Left: Matched Config & Lineage */}
            <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 backdrop-blur-md shadow-md space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                    Detection & Lineage Summary
                  </h4>
                </div>
                <Badge variant="vendor" size="sm">
                  {pipelineOutput.matchedConfig}
                </Badge>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-400">Vendor / Device:</span>
                  <span className="text-cyan-300 font-semibold">{pipelineOutput.matchedVendor}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Product / Model:</span>
                  <span className="text-slate-200">{pipelineOutput.matchedProduct}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target OCSF Class:</span>
                  <span className="text-purple-300 font-semibold">{pipelineOutput.normalizedEvent?.class_name} ({pipelineOutput.normalizedEvent?.class_uid})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Total Processing Time:</span>
                  <span className="text-emerald-400 font-semibold">{pipelineOutput.totalDurationMs} ms</span>
                </div>
              </div>

              <FieldLineageTable lineage={pipelineOutput.lineage} />
            </div>

            {/* Right: Normalized OCSF JSON Document */}
            <div className="bg-slate-900/80 rounded-xl p-5 border border-slate-800 backdrop-blur-md shadow-md space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                      Normalized OCSF JSON Document
                    </h4>
                  </div>
                  <span className="text-[11px] font-mono text-cyan-400">
                    UUID: {pipelineOutput.event_uid.substring(0, 8)}...
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-cyan-900/40 font-mono text-xs text-cyan-100/90 whitespace-pre overflow-y-auto max-h-[360px] shadow-inner">
                  {JSON.stringify(pipelineOutput.normalizedEvent, null, 2)}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={handleAddToLiveFeed}
                  className={`flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl text-xs font-semibold tracking-wide transition-all ${
                    recentlyAdded
                      ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30'
                  }`}
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{recentlyAdded ? 'Added to Live SOC Feed!' : 'Add Event to Live Feed'}</span>
                </button>

                {pipelineOutput.normalizedEvent && (
                  <button
                    onClick={() => onOpenDrilldown(pipelineOutput.normalizedEvent!)}
                    className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    <Eye className="w-4 h-4 text-cyan-400" />
                    <span>Forensic View</span>
                  </button>
                )}
              </div>

            </div>

          </div>
        </div>
      )}
    </div>
  );
};
