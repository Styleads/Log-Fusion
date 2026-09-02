import React, { useState } from 'react';
import { FileCode, Copy, Check, Download, Edit3, ShieldAlert, Save } from 'lucide-react';

interface YamlDraftViewerProps {
  yamlContent: string;
  onChangeYaml: (newYaml: string) => void;
  sourceName: string;
  slug: string;
  status: string;
}

export const YamlDraftViewer: React.FC<YamlDraftViewerProps> = ({
  yamlContent,
  onChangeYaml,
  sourceName,
  slug,
  status,
}) => {
  const [copied, setCopied] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(yamlContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([yamlContent], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${slug || 'mapping'}.yaml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl overflow-hidden flex flex-col h-full">
      {/* Top Header Bar */}
      <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-emerald-400" />
          <span className="text-xs font-bold text-white font-mono">
            Generated YAML Config (`mappings/{slug || 'unknown'}/mapping.yaml`)
          </span>
          <span
            className={`text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded ${
              status === 'reviewed'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
            }`}
          >
            {status}
          </span>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsEditing(!isEditing)}
            className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono rounded-lg transition-all border ${
              isEditing
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-slate-800 text-slate-300 hover:text-white border-slate-700'
            }`}
          >
            {isEditing ? <Save className="w-3.5 h-3.5" /> : <Edit3 className="w-3.5 h-3.5" />}
            <span>{isEditing ? 'Lock Edit' : 'Edit Inline'}</span>
          </button>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-slate-800 text-slate-300 hover:text-white rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied!' : 'Copy'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-slate-800 text-slate-300 hover:text-white rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download</span>
          </button>
        </div>
      </div>

      {/* Warning Review Banner */}
      {status === 'draft' && (
        <div className="bg-amber-950/40 border-b border-amber-800/40 px-4 py-2 flex items-center gap-2 text-amber-200/90 text-[11px] font-mono">
          <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            <b>Review Warning:</b> This configuration is auto-generated in <code>status: "draft"</code> mode. Please verify field mappings before approving.
          </span>
        </div>
      )}

      {/* YAML Editor / Viewer Area */}
      <div className="p-4 flex-1 bg-slate-950/70 overflow-auto font-mono text-xs leading-relaxed">
        {isEditing ? (
          <textarea
            value={yamlContent}
            onChange={(e) => onChangeYaml(e.target.value)}
            rows={22}
            className="w-full h-full min-h-[380px] p-3 rounded-xl bg-slate-950 border border-emerald-500/40 text-emerald-300 focus:outline-none focus:ring-1 focus:ring-emerald-500/60 font-mono text-xs leading-relaxed resize-y"
          />
        ) : (
          <pre className="text-slate-300 whitespace-pre-wrap font-mono text-xs select-text">
            {yamlContent.split('\n').map((line, i) => {
              const isComment = line.trim().startsWith('#');
              const isKey = line.includes(':') && !isComment;
              return (
                <div key={i} className="hover:bg-slate-800/30 px-1 py-0.5 rounded">
                  {isComment ? (
                    <span className="text-amber-400/90 italic font-semibold">{line}</span>
                  ) : isKey ? (
                    <>
                      <span className="text-cyan-400 font-bold">{line.split(':')[0]}:</span>
                      <span className="text-emerald-300">{line.substring(line.indexOf(':') + 1)}</span>
                    </>
                  ) : (
                    <span className="text-slate-300">{line}</span>
                  )}
                </div>
              );
            })}
          </pre>
        )}
      </div>
    </div>
  );
};
