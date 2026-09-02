import React from 'react';
import { FolderCheck, ShieldAlert, CheckCircle2, ArrowRight, RefreshCw, FileText } from 'lucide-react';
import { DraftMappingItem } from '../../types/assistant';

interface DraftsDrawerProps {
  drafts: DraftMappingItem[];
  onApprove: (slug: string) => void;
  onSelectDraft?: (draft: DraftMappingItem) => void;
  isApprovingSlug: string | null;
  onRefresh: () => void;
}

export const DraftsDrawer: React.FC<DraftsDrawerProps> = ({
  drafts,
  onApprove,
  onSelectDraft,
  isApprovingSlug,
  onRefresh,
}) => {
  return (
    <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <FolderCheck className="w-5 h-5 text-cyan-400" />
          <div>
            <h4 className="text-sm font-bold text-white font-mono tracking-wide">
              Onboarded & Draft Config Queue ({drafts.length})
            </h4>
            <p className="text-xs text-slate-400">
              Auto-generated mapping files stored under <code>/mappings</code> requiring human approval.
            </p>
          </div>
        </div>

        <button
          onClick={onRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 rounded-lg border border-slate-700 transition-all cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh List</span>
        </button>
      </div>

      {drafts.length === 0 ? (
        <div className="p-6 text-center rounded-xl bg-slate-950/60 border border-slate-800/60 text-slate-400 text-xs font-mono">
          No pending draft configurations. Analyze sample log lines above to create a starter YAML mapping!
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {drafts.map((draft) => {
            const isApproved = draft.status === 'reviewed';
            return (
              <div
                key={draft.slug}
                className={`p-4 rounded-xl border transition-all flex flex-col justify-between gap-3 ${
                  isApproved
                    ? 'bg-slate-950/80 border-emerald-500/30'
                    : 'bg-slate-950 border-slate-800 hover:border-cyan-500/50'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-bold text-white font-mono truncate">
                      {draft.source_name || draft.product}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${
                        isApproved
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {draft.status}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                    <div>Format: <span className="text-slate-200 uppercase">{draft.format}</span></div>
                    <div>File: <code className="text-cyan-300/90">{draft.file_path}</code></div>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                  {onSelectDraft && draft.yaml_content && (
                    <button
                      onClick={() => onSelectDraft(draft)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 cursor-pointer"
                    >
                      <FileText className="w-3.5 h-3.5" />
                      <span>Inspect</span>
                    </button>
                  )}

                  {!isApproved ? (
                    <button
                      onClick={() => onApprove(draft.slug)}
                      disabled={isApprovingSlug === draft.slug}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white shadow-md shadow-emerald-500/20 transition-all cursor-pointer disabled:opacity-50"
                    >
                      {isApprovingSlug === draft.slug ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Deploying...</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Approve & Deploy Live</span>
                        </>
                      )}
                    </button>
                  ) : (
                    <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Active in Live Engine</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
