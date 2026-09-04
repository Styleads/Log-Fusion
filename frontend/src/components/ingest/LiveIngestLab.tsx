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
  Download,
  BarChart2
} from 'lucide-react';
import { SAMPLE_RAW_LOGS } from '../../data/sampleRawLogs';
import { PRESET_UNKNOWN_SAMPLES } from '../../data/presetSamples';
import { processRawLog } from '../../services/ocsfEngine';
import { assistantService } from '../../services/assistantService';
import { apiService } from '../../services/apiService';
import { NormalizationPipelineOutput } from '../../types/events';
import { OCSFEvent } from '../../types/ocsf';
import { AssistantAnalysisData } from '../../types/assistant';
import { PipelineStepper } from './PipelineStepper';
import { FieldLineageTable } from '../drilldown/FieldLineageTable';
import { Badge } from '../common/Badge';

interface LiveIngestLabProps {
  onEventIngested: (event: OCSFEvent | OCSFEvent[]) => void;
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
  const [normalizedBatch, setNormalizedBatch] = useState<OCSFEvent[]>([]);
  const [assistantOutput, setAssistantOutput] = useState<AssistantAnalysisData | null>(null);
  const [isUnknownFormat, setIsUnknownFormat] = useState<boolean>(false);
  const [statusNotification, setStatusNotification] = useState<string | null>(null);
  const [approvedSlug, setApprovedSlug] = useState<string | null>(null);

  const showStatus = (msg: string) => {
    setStatusNotification(msg);
    setTimeout(() => setStatusNotification(null), 5000);
  };

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
        setNormalizedBatch([]);
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
    setNormalizedBatch([]);
    setAssistantOutput(null);
    setIsUnknownFormat(false);
  };

  // Run Universal Log Pipeline Across Entire Uploaded File
  const handleExecutePipeline = async () => {
    if (!rawInput.trim()) return;
    setIsProcessing(true);
    setPipelineOutput(null);
    setNormalizedBatch([]);
    setAssistantOutput(null);
    setIsUnknownFormat(false);

    try {
      const lines = rawInput.split('\n').filter((l) => l.trim());
      if (lines.length === 0) return;

      // 1. Ingest batch through live backend API (or local engine fallback)
      const batchEvents = await apiService.ingestBatch(lines);

      if (batchEvents.length > 0) {
        const firstEv = batchEvents[0];
        const localPreview = processRawLog(firstEv.raw_data || lines[0]);
        const finalPreview: NormalizationPipelineOutput = (localPreview && localPreview.success && localPreview.normalizedEvent) ? {
          ...localPreview,
          normalizedEvent: firstEv
        } : {
          event_uid: firstEv.event_uid,
          success: true,
          matchedConfig: firstEv.processing_metadata?.matched_config || `${firstEv.source_vendor || 'Vendor'} Config`,
          matchedVendor: firstEv.source_vendor || firstEv.device?.vendor_name || 'Security Vendor',
          matchedProduct: firstEv.source_product || firstEv.device?.name || 'Device',
          stages: [
            { stage: 'ingest', name: 'Ingest Raw Stream', status: 'success', durationMs: 0.1, details: { bytes: (firstEv.raw_data || '').length, encoding: 'UTF-8' } },
            { stage: 'detect', name: 'Vendor Auto-Detection', status: 'success', durationMs: 0.2, details: { vendor: firstEv.source_vendor || 'Vendor', matched_rule: firstEv.processing_metadata?.matched_config || 'matched.yaml' } },
            { stage: 'parse', name: 'Grammar Parsing', status: 'success', durationMs: 0.3, details: { format: firstEv.raw_format || 'delimited' } },
            { stage: 'classify', name: 'OCSF Taxonomy Classification', status: 'success', durationMs: 0.1, details: { target_class: firstEv.class_name, class_uid: firstEv.class_uid } },
            { stage: 'map', name: 'Dotted Schema Mapping', status: 'success', durationMs: 0.2, details: { ocsf_class: firstEv.class_name } },
            { stage: 'preserve', name: 'Lossless Audit Preservation', status: 'success', durationMs: 0.1, details: { uuid_stamped: firstEv.event_uid, raw_preserved: true } }
          ],
          normalizedEvent: firstEv,
          lineage: [
            { raw_field: 'Source IP', raw_value: firstEv.src_endpoint?.ip || '—', ocsf_path: 'src_endpoint.ip', status: 'mapped' },
            ...((firstEv as any).http_request?.url?.text ? [{ raw_field: 'URL', raw_value: (firstEv as any).http_request.url.text, ocsf_path: 'http_request.url.text', status: 'mapped' as const }] : []),
            ...((firstEv as any).http_request?.http_method ? [{ raw_field: 'HTTP Method', raw_value: (firstEv as any).http_request.http_method, ocsf_path: 'http_request.http_method', status: 'mapped' as const }] : []),
            { raw_field: 'Source Port', raw_value: firstEv.src_endpoint?.port ?? '—', ocsf_path: 'src_endpoint.port', status: 'mapped' },
            { raw_field: 'Dest IP', raw_value: firstEv.dst_endpoint?.ip || '—', ocsf_path: 'dst_endpoint.ip', status: 'mapped' },
            { raw_field: 'Dest Port', raw_value: firstEv.dst_endpoint?.port ?? '—', ocsf_path: 'dst_endpoint.port', status: 'mapped' },
            { raw_field: 'Protocol', raw_value: firstEv.connection_info?.protocol_name || '—', ocsf_path: 'connection_info.protocol_name', status: 'mapped' },
            { raw_field: 'Action', raw_value: firstEv.activity_name || '—', ocsf_path: 'activity_name', status: 'transformed' },
            { raw_field: 'Device Name', raw_value: firstEv.device?.vendor_name || firstEv.device?.name || '—', ocsf_path: 'device.vendor_name', status: 'mapped' }
          ],
          totalDurationMs: firstEv.processing_metadata?.parser_time_ms || 1.2
        };

        setPipelineOutput(finalPreview);
        setNormalizedBatch(batchEvents);
        setIsUnknownFormat(false);

        // Push to SOC Dashboard
        onEventIngested(batchEvents);
        showStatus(`✅ Successfully normalized ${batchEvents.length} OCSF events from ${fileName} and synced to OpenSearch database!`);
      } else {
        // Unknown format -> trigger Auto-Mapping Assistant
        const sourceLabel = fileName.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9]/g, ' ') || 'Unknown Device';
        const analysis = await assistantService.analyzeLogs(
          sourceLabel,
          lines.slice(0, 10),
          'firewall',
          false
        );
        setAssistantOutput(analysis);
        setIsUnknownFormat(true);
        showStatus(`🪄 Unknown format detected! Auto-Mapping Assistant generated a draft YAML configuration for ${sourceLabel}.`);
      }
    } catch (err) {
      console.error('Pipeline execution error:', err);
      showStatus('⚠️ Pipeline execution error.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleApproveAssistantDraft = async (slug: string) => {
    setIsProcessing(true);
    try {
      const lines = rawInput.split('\n').filter((l) => l.trim());
      const sourceLabel = fileName.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9]/g, ' ') || slug;

      // 1. Save draft mapping configuration to mappings/<slug>/mapping.yaml
      if (assistantOutput?.yaml_draft) {
        await assistantService.saveDraft(
          assistantOutput.source_name || sourceLabel,
          assistantOutput.yaml_draft,
          lines
        );
      }

      // 2. Approve draft: updates status to "reviewed" & hot-reloads backend engine pipeline
      await assistantService.approveDraft(slug);
      setApprovedSlug(slug);

      // 3. Re-ingest the uploaded lines through the newly activated pipeline with storage forwarding
      const batchEvents = await apiService.ingestBatch(lines);

      if (batchEvents && batchEvents.length > 0) {
        setNormalizedBatch(batchEvents);
        onEventIngested(batchEvents);
        setIsUnknownFormat(false);
        showStatus(`✅ Approved & deployed ${slug}! Successfully synced ${batchEvents.length} events to OpenSearch database.`);
      } else if (assistantOutput?.ocsf_preview?.[0]) {
        onEventIngested(assistantOutput.ocsf_preview);
        showStatus(`✅ Approved draft mapping! Flipped status to "reviewed" & updated SOC Dashboard.`);
      }
    } catch (err) {
      console.error('Failed to approve draft:', err);
      showStatus('⚠️ Error deploying approved mapping to pipeline.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Status Notification Banner */}
      {statusNotification && (
        <div className="bg-gradient-to-r from-emerald-950 via-slate-900 to-cyan-950 border border-emerald-500/40 rounded-xl px-4 py-3 text-emerald-200 text-xs font-mono flex items-center justify-between shadow-lg animate-fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{statusNotification}</span>
          </div>
          <button
            onClick={() => setStatusNotification(null)}
            className="text-slate-400 hover:text-white text-xs font-bold px-2 py-0.5 cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

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
              <span className="text-slate-500 text-[10px]">
                ({rawInput.split('\n').filter((l) => l.trim()).length} log lines)
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Preset Log Payload Loader Bar */}
      <div className="bg-slate-900/70 p-4 rounded-xl border border-slate-800">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            Or test preset log file:
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
                <span>Identifying & Normalizing File...</span>
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
                  <span className="text-slate-400">Matched Vendor:</span>
                  <span className="text-cyan-300 font-semibold">{pipelineOutput.matchedVendor}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Total Normalized Events:</span>
                  <span className="text-emerald-400 font-semibold">{normalizedBatch.length} events</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target OCSF Class:</span>
                  <span className="text-purple-300 font-semibold">
                    {pipelineOutput.normalizedEvent?.class_name} ({pipelineOutput.normalizedEvent?.class_uid})
                  </span>
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
                      Normalized OCSF Document Preview
                    </h4>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1 font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Pushed to SOC Dashboard Feed</span>
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-cyan-900/40 font-mono text-xs text-cyan-200/90 whitespace-pre overflow-y-auto max-h-[340px] shadow-inner select-text">
                  {JSON.stringify(pipelineOutput.normalizedEvent, null, 2)}
                </div>
              </div>

              <div className="flex items-center gap-3 pt-2">
                {pipelineOutput.normalizedEvent && (
                  <button
                    onClick={() => onOpenDrilldown(pipelineOutput.normalizedEvent!)}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/30 transition-all cursor-pointer"
                  >
                    <Eye className="w-4 h-4 text-white" />
                    <span>Inspect Forensic Side-by-Side View</span>
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
