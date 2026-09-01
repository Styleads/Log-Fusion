import React from 'react';
import { CheckCircle2, Clock, AlertCircle, ArrowRight, ShieldCheck, Database, Search, GitBranch, Cpu, Lock } from 'lucide-react';
import { PipelineStageResult } from '../../types/events';

interface PipelineStepperProps {
  stages: PipelineStageResult[];
  activeStageIndex?: number;
}

export const PipelineStepper: React.FC<PipelineStepperProps> = ({ stages }) => {
  const iconMap: Record<string, any> = {
    ingest: Database,
    detect: Search,
    parse: Cpu,
    classify: ShieldCheck,
    map: GitBranch,
    preserve: Lock
  };

  return (
    <div className="bg-slate-950/80 rounded-xl p-4 sm:p-5 border border-slate-800 shadow-inner">
      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono mb-4 flex items-center justify-between">
        <span>6-Stage Normalization Pipeline Telemetry</span>
        <span className="text-cyan-400 font-normal">Real-Time Execution</span>
      </h4>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {stages.map((stage, idx) => {
          const Icon = iconMap[stage.stage] || Clock;
          const isSuccess = stage.status === 'success';
          const isError = stage.status === 'error';
          const isRunning = stage.status === 'running';

          return (
            <div
              key={stage.stage}
              className={`relative rounded-xl p-3 border transition-all duration-300 ${
                isSuccess
                  ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.1)]'
                  : isRunning
                  ? 'bg-cyan-950/30 border-cyan-400 text-cyan-300 animate-pulse'
                  : isError
                  ? 'bg-rose-950/30 border-rose-500 text-rose-300'
                  : 'bg-slate-900/60 border-slate-800 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-slate-400">
                  0{idx + 1}
                </span>
                {isSuccess && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                {isRunning && <Clock className="w-3.5 h-3.5 text-cyan-400 animate-spin" />}
                {isError && <AlertCircle className="w-3.5 h-3.5 text-rose-400" />}
              </div>

              <div className="flex items-center gap-1.5 mb-1">
                <Icon className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                <h5 className="text-xs font-semibold tracking-tight truncate text-slate-200">
                  {stage.name.split(' ')[0]}
                </h5>
              </div>

              <p className="text-[10px] text-slate-400 truncate">
                {stage.name}
              </p>

              {stage.durationMs !== undefined && (
                <div className="mt-2 text-[10px] font-mono text-cyan-400 font-medium">
                  {stage.durationMs} ms
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
