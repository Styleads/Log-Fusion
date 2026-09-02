import React, { useState, useEffect } from 'react';
import { Sparkles, Save, CheckCircle2, ShieldAlert, ArrowRight, Play, Terminal } from 'lucide-react';
import { SampleLogInput } from './SampleLogInput';
import { YamlDraftViewer } from './YamlDraftViewer';
import { ValidationPreview } from './ValidationPreview';
import { DraftsDrawer } from './DraftsDrawer';
import { assistantService } from '../../services/assistantService';
import { AssistantAnalysisData, DraftMappingItem } from '../../types/assistant';
import { OCSFEvent } from '../../types/ocsf';
import { PRESET_UNKNOWN_SAMPLES } from '../../data/presetSamples';

interface AutoMappingStudioProps {
  onEventIngested?: (event: OCSFEvent) => void;
  onOpenDrilldown?: (event: OCSFEvent) => void;
}

export const AutoMappingStudio: React.FC<AutoMappingStudioProps> = ({
  onEventIngested,
  onOpenDrilldown,
}) => {
  // Input State
  const defaultPreset = PRESET_UNKNOWN_SAMPLES[0];
  const [sourceName, setSourceName] = useState<string>(defaultPreset.name);
  const [deviceType, setDeviceType] = useState<string>(defaultPreset.deviceType);
  const [useLlm, setUseLlm] = useState<boolean>(false);
  const [rawInput, setRawInput] = useState<string>(defaultPreset.rawLines.join('\n'));

  // Analysis State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<AssistantAnalysisData | null>(null);
  const [yamlDraft, setYamlDraft] = useState<string>('');

  // Drafts Queue State
  const [drafts, setDrafts] = useState<DraftMappingItem[]>([]);
  const [isApprovingSlug, setIsApprovingSlug] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Load initial analysis and draft queue
  useEffect(() => {
    const init = async () => {
      // Auto-analyze initial preset on load
      handleRunAnalysis();
      // Load drafts
      loadDrafts();
    };
    init();
  }, []);

  const loadDrafts = async () => {
    const list = await assistantService.listDrafts();
    setDrafts(list);
  };

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const handleRunAnalysis = async () => {
    if (!sourceName.trim() || !rawInput.trim()) return;

    setIsAnalyzing(true);
    const rawLines = rawInput.split('\n').filter((l) => l.trim());

    try {
      const data = await assistantService.analyzeLogs(
        sourceName,
        rawLines,
        deviceType,
        useLlm
      );

      setAnalysisResult(data);
      setYamlDraft(data.yaml_draft);
      showToast(`✨ Generated draft mapping for "${sourceName}" (${data.detected_format})`);
    } catch (err) {
      console.error('Error analyzing logs:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSaveDraft = async () => {
    if (!sourceName.trim() || !yamlDraft.trim()) return;

    setIsSaving(true);
    const rawLines = rawInput.split('\n').filter((l) => l.trim());

    try {
      const saveRes = await assistantService.saveDraft(
        sourceName,
        yamlDraft,
        rawLines
      );

      showToast(`💾 Saved draft under mappings/${saveRes.slug}/mapping.yaml`);
      await loadDrafts();
    } catch (err) {
      console.error('Error saving draft:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleApproveDraft = async (slug: string) => {
    setIsApprovingSlug(slug);
    try {
      await assistantService.approveDraft(slug);
      showToast(`✅ Approved "${slug}"! Flipped status to "reviewed" & hot-reloaded engine.`);
      await loadDrafts();

      // If we have an OCSF preview event, push it to live feed
      if (analysisResult?.ocsf_preview?.[0] && onEventIngested) {
        onEventIngested(analysisResult.ocsf_preview[0]);
      }
    } catch (err) {
      console.error('Error approving draft:', err);
    } finally {
      setIsApprovingSlug(null);
    }
  };

  const handleSelectDraft = (draft: DraftMappingItem) => {
    if (draft.yaml_content) {
      setYamlDraft(draft.yaml_content);
      setSourceName(draft.source_name);
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast Notification Banner */}
      {toastMessage && (
        <div className="bg-gradient-to-r from-cyan-950 via-slate-900 to-emerald-950 border border-cyan-500/40 rounded-xl px-4 py-3 text-cyan-200 text-xs font-mono flex items-center justify-between shadow-lg animate-fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{toastMessage}</span>
          </div>
          <button
            onClick={() => setToastMessage(null)}
            className="text-slate-400 hover:text-white text-xs font-bold px-2 py-0.5 cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {/* Hero Studio Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-cyan-950/40 to-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500 to-sky-600 text-white shadow-md shadow-cyan-500/30">
                <Sparkles className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white font-mono tracking-wide">
                  Auto-Mapping Assistant Studio
                </h2>
                <p className="text-xs text-cyan-300 font-mono mt-0.5">
                  Unknown Log ➔ Heuristic Format Detection ➔ Starter YAML ➔ OCSF Pipeline Preview ➔ Deploy
                </p>
              </div>
            </div>
          </div>

          {/* Quick Action Save Draft Button */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleSaveDraft}
              disabled={isSaving || !yamlDraft}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-xs tracking-wider uppercase font-mono bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-500/25 transition-all cursor-pointer disabled:opacity-50"
            >
              {isSaving ? (
                <span>Saving Draft...</span>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save Draft Config</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Main Studio Grid: Input (Left) + Generated Outputs (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Step 1: Input Panel (5 Columns) */}
        <div className="lg:col-span-5">
          <SampleLogInput
            sourceName={sourceName}
            setSourceName={setSourceName}
            deviceType={deviceType}
            setDeviceType={setDeviceType}
            useLlm={useLlm}
            setUseLlm={setUseLlm}
            rawInput={rawInput}
            setRawInput={setRawInput}
            onAnalyze={handleRunAnalysis}
            isAnalyzing={isAnalyzing}
          />
        </div>

        {/* Step 2 & 3: YAML Viewer & OCSF Validation Preview (7 Columns) */}
        <div className="lg:col-span-7 space-y-6 flex flex-col">
          {/* Generated YAML Config */}
          <div className="flex-1 min-h-[360px]">
            <YamlDraftViewer
              yamlContent={yamlDraft || '# Click "Generate Draft YAML Config" to analyze input lines...'}
              onChangeYaml={setYamlDraft}
              sourceName={sourceName}
              slug={analysisResult?.slug || 'unknown'}
              status={analysisResult ? 'draft' : 'draft'}
            />
          </div>

          {/* OCSF Live Pipeline Validation Preview */}
          {analysisResult && (
            <div className="flex-1 min-h-[300px]">
              <ValidationPreview
                detectedFormat={analysisResult.detected_format}
                confidenceScore={analysisResult.confidence_score}
                confidenceLabel={analysisResult.confidence_label}
                validation={analysisResult.validation}
                ocsfPreview={analysisResult.ocsf_preview}
                onOpenDrilldown={onOpenDrilldown}
              />
            </div>
          )}
        </div>
      </div>

      {/* Step 4: Pending Drafts & Approved Config Queue */}
      <DraftsDrawer
        drafts={drafts}
        onApprove={handleApproveDraft}
        onSelectDraft={handleSelectDraft}
        isApprovingSlug={isApprovingSlug}
        onRefresh={loadDrafts}
      />
    </div>
  );
};
