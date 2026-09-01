import React from 'react';
import { X, Sparkles, Terminal } from 'lucide-react';
import { LiveIngestLab } from './LiveIngestLab';
import { OCSFEvent } from '../../types/ocsf';

interface InstantIngestModalProps {
  isOpen: boolean;
  onClose: () => void;
  onEventIngested: (event: OCSFEvent) => void;
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
      <div className="relative w-full max-w-5xl max-h-[90vh] flex flex-col rounded-3xl bg-[#0e111d] border border-slate-700 shadow-2xl shadow-purple-950/50 overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/80 bg-[#131627]">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-2xl bg-purple-500/15 text-purple-400 border border-purple-500/30">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                Instant Log Ingest & Normalization Lab
              </h3>
              <p className="text-xs text-slate-400">
                Execute the 6-stage OCSF pipeline on live or preset perimeter logs
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-2xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-100px)]">
          <LiveIngestLab
            onEventIngested={(e) => {
              onEventIngested(e);
              onClose();
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
