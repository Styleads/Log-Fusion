import React from 'react';
import { Sparkles, Terminal, FileCode, Cpu, RotateCcw, Play, CheckCircle2 } from 'lucide-react';
import { PRESET_UNKNOWN_SAMPLES } from '../../data/presetSamples';
import { PresetSampleLog } from '../../types/assistant';

interface SampleLogInputProps {
  sourceName: string;
  setSourceName: (val: string) => void;
  deviceType: string;
  setDeviceType: (val: string) => void;
  useLlm: boolean;
  setUseLlm: (val: boolean) => void;
  rawInput: string;
  setRawInput: (val: string) => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
}

export const SampleLogInput: React.FC<SampleLogInputProps> = ({
  sourceName,
  setSourceName,
  deviceType,
  setDeviceType,
  useLlm,
  setUseLlm,
  rawInput,
  setRawInput,
  onAnalyze,
  isAnalyzing,
}) => {
  const handleLoadPreset = (preset: PresetSampleLog) => {
    setSourceName(preset.name);
    setDeviceType(preset.deviceType);
    setRawInput(preset.rawLines.join('\n'));
  };

  const handleClear = () => {
    setSourceName('');
    setRawInput('');
  };

  return (
    <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800 shadow-xl space-y-5">
      {/* Header Title */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white font-mono tracking-wide">
              1. Source & Raw Payload Input
            </h3>
            <p className="text-xs text-slate-400">
              Provide sample log lines from an un-onboarded device to infer rules and generate starter YAML.
            </p>
          </div>
        </div>

        <button
          onClick={handleClear}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-800 rounded-lg border border-slate-700/60 transition-all cursor-pointer"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset</span>
        </button>
      </div>

      {/* Preset Log Payload Buttons */}
      <div>
        <label className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 font-mono block mb-2">
          ⚡ Load Sample from Unknown Device Vendor:
        </label>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {PRESET_UNKNOWN_SAMPLES.map((preset) => (
            <button
              key={preset.id}
              onClick={() => handleLoadPreset(preset)}
              className="group flex flex-col items-start p-2.5 rounded-xl bg-slate-950/80 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer text-left"
            >
              <div className="flex items-center justify-between w-full">
                <span className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 font-mono">
                  {preset.vendor}
                </span>
                <span className="text-[10px] font-mono text-slate-500 px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
                  {preset.format}
                </span>
              </div>
              <span className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                {preset.name}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Inputs: Source Name & Device Hint */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
        <div>
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono block mb-1.5">
            Log Source Name:
          </label>
          <input
            type="text"
            value={sourceName}
            onChange={(e) => setSourceName(e.target.value)}
            placeholder="e.g. SonicWall NSa Gateway"
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-600 text-xs font-mono focus:outline-none focus:border-cyan-500 transition-all"
          />
        </div>

        <div>
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono block mb-1.5">
            Device Category Hint:
          </label>
          <select
            value={deviceType}
            onChange={(e) => setDeviceType(e.target.value)}
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 text-xs font-mono focus:outline-none focus:border-cyan-500 transition-all"
          >
            <option value="firewall">Firewall (Perimeter Gateway)</option>
            <option value="ids">IDS / IPS Threat Sensor</option>
            <option value="vpn">VPN Access Gateway</option>
            <option value="router">Core / Edge Router</option>
            <option value="proxy">WAF / Reverse Proxy</option>
          </select>
        </div>
      </div>

      {/* Textarea for Raw Lines */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Raw Log Lines (5–20 Sample Lines):</span>
          </label>
          <span className="text-[10px] font-mono text-slate-500">
            {rawInput.split('\n').filter((l) => l.trim()).length} lines loaded
          </span>
        </div>

        <textarea
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          rows={6}
          placeholder="Paste raw log lines here..."
          className="w-full p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-700 text-xs font-mono leading-relaxed focus:outline-none focus:border-cyan-500/70 transition-all resize-y"
        />
      </div>

      {/* Advanced LLM Toggle & Submit Button */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2 border-t border-slate-800/80">
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <input
            type="checkbox"
            checked={useLlm}
            onChange={(e) => setUseLlm(e.target.checked)}
            className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-cyan-500/40 cursor-pointer"
          />
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs text-slate-300 group-hover:text-white font-mono transition-colors">
              Enable 1-Shot Local Ollama Fallback (For ambiguous fields)
            </span>
          </div>
        </label>

        <button
          onClick={onAnalyze}
          disabled={isAnalyzing || !sourceName.trim() || !rawInput.trim()}
          className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3 rounded-xl font-bold text-xs tracking-wider uppercase font-mono bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          {isAnalyzing ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Analyzing & Drafting Config...</span>
            </>
          ) : (
            <>
              <Sparkles className="w-4 h-4 fill-current" />
              <span>Generate Draft YAML Config</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
