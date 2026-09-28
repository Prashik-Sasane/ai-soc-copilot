'use client';

import React, { useEffect, useState } from 'react';
import {
  Grid,
  ShieldAlert,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
  Loader2,
  AlertCircle,
  Activity
} from 'lucide-react';
import { getMitreMatrix, triggerSyntheticScenario, triggerCorrelation } from '@/lib/api';

type TechniqueT = {
  technique_id: string;
  name: string;
  description: string;
  platforms: string[];
  detected: boolean;
  severity?: string;
  confidence?: number;
  rationale?: string;
};

type TacticT = {
  id: string;
  name: string;
  count: number;
  techniques: TechniqueT[];
};

type MatrixResponse = {
  tactics: TacticT[];
  summary?: {
    total_techniques: number;
    detected_techniques: number;
    incidents_scanned: number;
    alerts_scanned: number;
  };
};

const severityStyles: Record<string, string> = {
  critical: 'bg-rose-950/40 border-rose-800/40 text-rose-200',
  high: 'bg-amber-950/40 border-amber-800/40 text-amber-200',
  medium: 'bg-cyan-950/40 border-cyan-800/40 text-cyan-200',
  low: 'bg-emerald-950/40 border-emerald-800/40 text-emerald-200',
};

export default function MitrePage() {
  const [data, setData] = useState<MatrixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getMitreMatrix();
      setData(res as MatrixResponse);
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to load MITRE matrix');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerateData = async () => {
    setGenerating(true);
    setError(null);
    try {
      await triggerSyntheticScenario();
      try {
        await triggerCorrelation();
      } catch {}
      await loadData();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to generate data');
    } finally {
      setGenerating(false);
    }
  };

  const tactics = data?.tactics || [];
  const totalDetected = tactics.reduce((s, t) => s + t.count, 0);
  const totalTechs = tactics.reduce((s, t) => s + t.techniques.length, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Grid className="w-6 h-6 text-cyan-400" />
            <span>MITRE ATT&CK Matrix Explorer</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Observed adversary tactics & techniques mapped across enterprise telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-cyan-500/50 transition-all text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleGenerateData}
            disabled={generating}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium transition-all shadow-cyan-glow disabled:opacity-50"
          >
            {generating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
            {generating ? 'Generating...' : 'Generate Attack Data'}
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      {data?.summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-soc-textMuted uppercase tracking-wider font-mono">Coverage</p>
            <p className="text-xl font-bold text-white mt-1">
              {data.summary.total_techniques} <span className="text-xs text-soc-textMuted font-normal">Techniques</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-rose-400 uppercase tracking-wider font-mono">Active Detections</p>
            <p className="text-xl font-bold text-rose-400 mt-1">
              {data.summary.detected_techniques} <span className="text-xs text-soc-textMuted font-normal">Techniques</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-amber-400 uppercase tracking-wider font-mono">Incidents Scanned</p>
            <p className="text-xl font-bold text-amber-400 mt-1">
              {data.summary.incidents_scanned} <span className="text-xs text-soc-textMuted font-normal">Total</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-cyan-400 uppercase tracking-wider font-mono">Alerts Scanned</p>
            <p className="text-xl font-bold text-cyan-400 mt-1">
              {data.summary.alerts_scanned} <span className="text-xs text-soc-textMuted font-normal">Total</span>
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="glass-panel p-4 rounded-2xl border border-rose-800/50 bg-rose-950/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-rose-300 font-semibold">Error</p>
            <p className="text-xs text-rose-200/70 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {loading ? (
        <div className="glass-panel p-16 rounded-2xl border border-soc-cardBorder text-center">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-sm text-soc-textMuted font-mono">Analyzing alerts and incidents for MITRE ATT&CK mapping...</p>
        </div>
      ) : (
        <>
          {totalDetected === 0 && totalTechs > 0 && (
            <div className="glass-panel p-5 rounded-2xl border border-cyan-800/40 bg-cyan-950/10 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm text-cyan-300 font-semibold">No detections yet</p>
                <p className="text-xs text-cyan-200/70 mt-0.5">
                  The system found no evidence matching ATT&CK techniques in your current tenant workspace.
                  Click <span className="font-mono text-cyan-300">&quot;Generate Attack Data&quot;</span> to seed a synthetic
                  multi-stage attack scenario and see detections populate the matrix.
                </p>
              </div>
              <button
                onClick={handleGenerateData}
                disabled={generating}
                className="shrink-0 px-3 py-1.5 rounded-lg bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 hover:bg-cyan-900/60 text-xs font-medium transition-all disabled:opacity-50"
              >
                Generate Scenario
              </button>
            </div>
          )}

          {/* Grid columns of tactics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {tactics
              .filter((t) => t.techniques.length > 0)
              .map((tactic) => (
                <div
                  key={tactic.id}
                  className="glass-panel p-4 rounded-2xl border border-soc-cardBorder space-y-3 flex flex-col"
                >
                  <div className="flex items-center justify-between border-b border-soc-cardBorder pb-2">
                    <span className="font-bold text-sm text-white leading-snug pr-2">{tactic.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded border text-xs font-mono shrink-0 ${
                        tactic.count > 0
                          ? 'bg-rose-950/60 border-rose-800/40 text-rose-300'
                          : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted'
                      }`}
                    >
                      {tactic.count} Detected
                    </span>
                  </div>

                  <div className="space-y-2 flex-1">
                    {tactic.techniques.length === 0 ? (
                      <div className="text-xs text-soc-textMuted italic py-4 text-center">
                        No technique references available
                      </div>
                    ) : (
                      tactic.techniques.map((tech) => (
                        <div
                          key={tech.technique_id}
                          className={`p-3 rounded-xl border text-xs space-y-1.5 ${
                            tech.detected
                              ? severityStyles[tech.severity || 'medium']
                              : 'bg-soc-sidebar/60 border-soc-cardBorder/60 text-soc-textMuted/70 opacity-70'
                          }`}
                        >
                          <div className="flex items-center justify-between font-mono text-[11px]">
                            <span className={`font-bold ${tech.detected ? '' : 'text-soc-textMuted/60'}`}>
                              {tech.technique_id}
                            </span>
                            <div className="flex items-center gap-2">
                              {tech.confidence !== undefined && tech.confidence !== null && (
                                <span className="text-[10px] opacity-80">
                                  {Math.round(tech.confidence * 100)}%
                                </span>
                              )}
                              {tech.detected ? (
                                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                              ) : (
                                <span className="text-[10px] font-mono opacity-50">undetected</span>
                              )}
                            </div>
                          </div>
                          <div className="font-semibold leading-snug">{tech.name}</div>
                          {tech.rationale && (
                            <p className="text-[10px] opacity-80 font-mono italic bg-soc-card/60 p-2 rounded border border-soc-cardBorder/60">
                              {tech.rationale}
                            </p>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
