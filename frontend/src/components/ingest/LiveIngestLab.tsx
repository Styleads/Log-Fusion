import React, { useState, useRef } from 'react';
import {
  Upload,
  FileText,
  Sparkles,
  Terminal,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  RefreshCw,
  Eye,
  Wand2,
  ArrowRight,
  ShieldCheck,
  Copy,
  Download
} from 'lucide-react';
import { SAMPLE_RAW_LOGS, SampleLogItem } from '../../data/sampleRawLogs';
import { PRESET_UNKNOWN_SAMPLES } from '../../data/presetSamples';
import { processRawLog } from '../../services/ocsfEngine';
import { assistantService } from '../../services/assistantService';
import { NormalizationPipelineOutput } from '../../types/events';
import { OCSFEvent } from '../../types/ocsf';
import { AssistantAnalysisData } from '../../types/assistant';
import { PipelineStepper } from './PipelineStepper';
import { FieldLineageTable } from '../drilldown/FieldLineageTable';
import { Badge } from '../common/Badge';

interface LiveIngestLabProps {
  onEventIngested: (event: OCSFEvent) => void;
  onOpenDrilldown: (event: OCSFEvent) => void;
}

export const LiveIngestLab: React.FC<LiveIngestLabProps> = ({
  onEventIngested,
  onOpenDrilldown
}) => {
  // Upload & Raw Input State
  const [fileName, setFileName] = useState<string>('sample_firewall.log');
  const [rawInput, setRawInput] = useState<string>(SAMPLE_RAW_LOGS[0].raw);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Processing State
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [pipelineOutput, setPipelineOutput] = useState<NormalizationPipelineOutput | null>(null);
  const [assistantOutput, setAssistantOutput] = useState<AssistantAnalysisData | null>(null);
  const [isUnknownFormat, setIsUnknownFormat] = useState<boolean>(false);
  const [recentlyAdded, setRecentlyAdded] = useState<boolean>(false);
  const [approvedSlug, setApprovedSlug] = useState<string | null>(null);

  // Handle Drag & Drop File Upload
  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processUploadedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processUploadedFile(e.target.files[0]);
    }
  };

  const processUploadedFile = (file: File) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setRawInput(content);
        setPipelineOutput(null);
        setAssistantOutput(null);
        setIsUnknownFormat(false);
      }
    };
    reader.readAsText(file);
  };

  const handleSelectPreset = (raw: string, name: string) => {
    setFileName(name);
    setRawInput(raw);
    setPipelineOutput(null);
    setAssistantOutput(null);
    setIsUnknownFormat(false);
  };

  // Run Automatic Identification & Pipeline Execution
  const handleExecutePipeline = async () => {
    if (!rawInput.trim()) return;
    setIsProcessing(true);
    setPipelineOutput(null);
    setAssistantOutput(null);
    setIsUnknownFormat(false);
    setRecentlyAdded(false);

    // 1. First run core pipeline to check if format matches known vendor
    const lines = rawInput.split('\n').filter((l) => l.trim());
    const firstLine = lines[0] || rawInput;

    const output = processRawLog(firstLine);

    if (output.matchedConfig && output.matchedConfig !== 'Unknown' && output.normalizedEvent) {
      // Known Vendor Matched!
      setTimeout(() => {
        setPipelineOutput(output);
        setIsUnknownFormat(false);
        setIsProcessing(false);
      }, 400);
    } else {
      // Unknown Vendor Format -> Auto-Trigger Assistant!
      try {
        const sourceLabel = fileName.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9]/g, ' ') || 'Unknown Device';
        const analysis = await assistantService.analyzeLogs(
          sourceLabel,
          lines.slice(0, 10),
          'firewall',
          false
        );

        setTimeout(() => {
          setAssistantOutput(analysis);
          setIsUnknownFormat(true);
          setIsProcessing(false);
        }, 400);
      } catch (err) {
        console.error('Assistant analysis failed:', err);
        setIsProcessing(false);
      }
    }
  };

  const handleApproveAssistantDraft = async (slug: string) => {
    try {
      await assistantService.approveDraft(slug);
      setApprovedSlug(slug);
      if (assistantOutput?.ocsf_preview?.[0]) {
        onEventIngested(assistantOutput.ocsf_preview[0]);
        setRecentlyAdded(true);
      }
    } catch (err) {
      console.error('Failed to approve draft:', err);
    }
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
      {/* Drag & Drop File Upload Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleFileDrop}
        className={`relative p-6 rounded-2xl border-2 border-dashed transition-all duration-200 text-center ${
          isDragOver
            ? 'border-cyan-400 bg-cyan-950/30 scale-[1.01]'
            : 'border-slate-800 bg-slate-900/80 hover:border-slate-700'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
          accept=".log,.txt,.csv,.json,.ndjson"
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center gap-3">
          <div className="p-3.5 rounded-2xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/10">
            <Upload className="w-6 h-6" />
          </div>

          <div>
            <h3 className="text-sm font-bold text-white font-mono">
              Drop any raw perimeter log file here or{' '}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="text-cyan-400 hover:underline cursor-pointer"
              >
                browse files
              </button>
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Supports <code>.log</code>, <code>.csv</code>, <code>.json</code>, <code>.txt</code>, <code>.ndjson</code>. Universal auto-detection identifies vendor rules automatically.
            </p>
          </div>

          {fileName && (
            <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300">
              <FileText className="w-3.5 h-3.5" />
              <span>{fileName}</span>
              <span className="text-slate-500 text-[10px]">({rawInput.length} chars)</span>
            </div>
          )}
        </div>
      </div>

      {/* Preset Log Payload Loader Bar */}
      <div className="bg-slate-900/70 p-4 rounded-xl border border-slate-800">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            Or select sample payload:
          </label>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_RAW_LOGS.map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleSelectPreset(sample.raw, `${sample.name.toLowerCase().replace(/\s+/g, '_')}.log`)}
                className="px-2.5 py-1 rounded-lg text-xs font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all cursor-pointer"
              >
                {sample.name}
              </button>
            ))}
            {PRESET_UNKNOWN_SAMPLES.map((preset) => (
              <button
                key={preset.id}
                onClick={() => handleSelectPreset(preset.rawLines.join('\n'), `${preset.id}.log`)}
                className="px-2.5 py-1 rounded-lg text-xs font-mono bg-purple-950/40 hover:bg-purple-900/40 text-purple-300 border border-purple-800/40 transition-all cursor-pointer"
              >
                🪄 {preset.name} (Unknown)
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Raw Payload Textarea & Run Pipeline Trigger */}
      <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Loaded Log Payload Stream
            </h4>
          </div>

          <button
            onClick={handleExecutePipeline}
            disabled={isProcessing || !rawInput.trim()}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-xs tracking-wider uppercase font-mono bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/25 transition-all cursor-pointer disabled:opacity-50"
          >
            {isProcessing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Identifying & Normalizing...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Run Universal Pipeline</span>
              </>
            )}
          </button>
        </div>

        <textarea
          rows={4}
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          placeholder="Log lines will appear here upon upload..."
          className="w-full p-3.5 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-amber-200/90 focus:outline-none focus:border-cyan-500 leading-relaxed shadow-inner"
        />
      </div>

      {/* CASE A: KNOWN VENDOR MATCHED */}
      {pipelineOutput && !isUnknownFormat && (
        <div className="space-y-6 animate-slide-up">
          <PipelineStepper stages={pipelineOutput.stages} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Detection Summary */}
            <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                    Auto-Matched Vendor Rule
                  </h4>
                </div>
                <Badge variant="vendor" size="sm">
                  {pipelineOutput.matchedConfig}
                </Badge>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Vendor Name:</span>
                  <span className="text-cyan-300 font-semibold">{pipelineOutput.matchedVendor}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target OCSF Class:</span>
                  <span className="text-purple-300 font-semibold">
                    {pipelineOutput.normalizedEvent?.class_name} ({pipelineOutput.normalizedEvent?.class_uid})
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Processing Latency:</span>
                  <span className="text-emerald-400 font-semibold">{pipelineOutput.totalDurationMs} ms</span>
                </div>
              </div>

              <FieldLineageTable lineage={pipelineOutput.lineage} />
            </div>

            {/* OCSF Document Output */}
            <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                      Normalized OCSF Document
                    </h4>
                  </div>
                  <span className="text-[11px] font-mono text-cyan-400">
                    UUID: {pipelineOutput.event_uid.substring(0, 8)}...
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-cyan-900/40 font-mono text-xs text-cyan-200/90 whitespace-pre overflow-y-auto max-h-[340px] shadow-inner">
                  {JSON.stringify(pipelineOutput.normalizedEvent, null, 2)}
                </div>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={handleAddToLiveFeed}
                  className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold tracking-wide transition-all ${
                    recentlyAdded
                      ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30'
                  }`}
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{recentlyAdded ? 'Added to Live Feed!' : 'Add Event to Live Feed'}</span>
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

      {/* CASE B: UNKNOWN VENDOR FORMAT DETECTED -> AUTO-MAPPING ASSISTANT TRIGGERED */}
      {assistantOutput && isUnknownFormat && (
        <div className="space-y-6 animate-slide-up">
          {/* Assistant Triggered Alert Banner */}
          <div className="bg-gradient-to-r from-purple-950 via-slate-900 to-cyan-950 p-5 rounded-2xl border border-purple-500/40 shadow-xl">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-2xl bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-lg shadow-purple-500/20">
                  <Wand2 className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono">
                      Unknown Device Format Detected!
                    </h3>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 uppercase">
                      Auto-Mapping Assistant Triggered
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono mt-1">
                    Detected Format: <b className="text-cyan-300 uppercase">{assistantOutput.detected_format}</b> · Generated starter YAML mapping draft with <b className="text-emerald-400">{Math.round(assistantOutput.confidence_score * 100)}% confidence</b>.
                  </p>
                </div>
              </div>

              {approvedSlug === assistantOutput.slug ? (
                <span className="px-4 py-2 rounded-xl bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-mono font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Approved & Active Live!</span>
                </span>
              ) : (
                <button
                  onClick={() => handleApproveAssistantDraft(assistantOutput.slug)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white shadow-lg shadow-emerald-500/30 transition-all cursor-pointer"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Approve & Deploy Draft Live</span>
                </button>
              )}
            </div>
          </div>

          {/* Draft YAML & Validation Output Split */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Generated YAML Draft */}
            <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-emerald-400" />
                  Generated Starter YAML Draft (`mappings/{assistantOutput.slug}/mapping.yaml`)
                </span>
              </div>

              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-emerald-300 font-mono text-xs leading-relaxed overflow-y-auto max-h-[380px] whitespace-pre-wrap select-text">
                {assistantOutput.yaml_draft}
              </pre>
            </div>

            {/* OCSF Pipeline Validation Output */}
            <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white font-mono flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  Live OCSF Validation Preview
                </span>
                <span className="text-xs text-emerald-400 font-mono">
                  100% Lossless Raw Preservation
                </span>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-cyan-200/90 font-mono text-xs leading-relaxed overflow-y-auto max-h-[380px] whitespace-pre-wrap select-text">
                {JSON.stringify(assistantOutput.ocsf_preview[0] || assistantOutput.ocsf_preview, null, 2)}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
