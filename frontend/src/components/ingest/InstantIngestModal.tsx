import React from 'react';
import { X, Sparkles, Terminal, Upload } from 'lucide-react';
import { LiveIngestLab } from './LiveIngestLab';
import { OCSFEvent } from '../../types/ocsf';

interface InstantIngestModalProps {
  isOpen: boolean;
  onClose: () => void;
  onEventIngested: (event: OCSFEvent | OCSFEvent[]) => void;
  onOpenDrilldown: (event: OCSFEvent) => void;
}

export const InstantIngestModal: React.FC<InstantIngestModalProps> = ({
  isOpen,
  onClose,
  onEventIngested,
  onOpenDrilldown
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-3xl bg-[#0e111d] border border-slate-700 shadow-2xl shadow-purple-950/50 overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-[#131627]">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-2xl bg-gradient-to-tr from-cyan-500 to-sky-600 text-white shadow-md shadow-cyan-500/20">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                Universal Log Ingestion & Auto-Mapping Studio
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Drop any raw log file — automatic format detection, normalization, & embedded AI draft generator
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-2xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto max-h-[calc(92vh-90px)]">
          <LiveIngestLab
            onEventIngested={(e) => {
              onEventIngested(e);
            }}
            onOpenDrilldown={(e) => {
              onClose();
              onOpenDrilldown(e);
            }}
          />
        </div>

      </div>
    </div>
  );
};
