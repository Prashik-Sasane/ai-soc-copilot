'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Bot,
  Send,
  Sparkles,
  BookOpen,
  CheckCircle2,
  ThumbsUp,
  ThumbsDown,
  AlertTriangle,
  Grid,
  ShieldCheck,
  RotateCcw,
  Zap,
  History,
  Loader2,
  RefreshCw,
  AlertCircle,
  Clock,
  Lightbulb
} from 'lucide-react';
import {
  queryCopilot,
  CopilotResponse,
  submitFeedback,
  getCopilotHistory,
  seedDemoScenario,
  seedKnowledgePlaybooks
} from '@/lib/api';

function CopilotContent() {
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get('query') || '';
  const alertId = searchParams.get('alert_id') || undefined;
  const incidentId = searchParams.get('incident_id') || undefined;

  const [inputQuery, setInputQuery] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<CopilotResponse | null>(null);
  const [feedbackGiven, setFeedbackGiven] = useState<string | null>(null);
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [history, setHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const presetQueries = [
    'Explain LSASS memory dump alert on WORKSTATION-089 and give containment steps.',
    'What evidence links the phishing email to the outbound C2 connection?',
    'Summarize threat actor tactics and MITRE ATT&CK techniques observed.',
    'Recommend automated response actions for credential dumping.',
  ];

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const h = await getCopilotHistory(20);
      setHistory(h || []);
    } catch (e) {
      console.error(e);
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleRunQuery = async (queryToRun?: string) => {
    const targetQuery =
      queryToRun ||
      inputQuery ||
      (alertId ? `Investigate alert ${alertId}` : incidentId ? `Investigate incident ${incidentId}` : '');
    if (!targetQuery.trim()) return;

    setLoading(true);
    setFeedbackGiven(null);
    setError(null);
    try {
      const res = await queryCopilot(targetQuery, incidentId, alertId);
      setResponse(res);
      loadHistory();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Copilot investigation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleFeedback = async (rating: string) => {
    if (!response?.investigation_id) return;
    setSubmittingFeedback(true);
    try {
      await submitFeedback(response.investigation_id, rating);
      setFeedbackGiven(rating);
    } catch (e) {
      console.error(e);
    } finally {
      setSubmittingFeedback(false);
    }
  };

  const handleSeedDemo = async () => {
    setLoading(true);
    setError(null);
    try {
      await seedKnowledgePlaybooks().catch(() => {});
      await seedDemoScenario().catch(() => {});
      setTimeout(() => {
        handleRunQuery(
          'Analyze all recent alerts. Summarize the attack chain, identify MITRE ATT&CK techniques, and recommend containment steps.'
        );
      }, 200);
    } catch (e: any) {
      setError(e?.message || 'Failed to seed data');
      setLoading(false);
    }
  };

  useEffect(() => {
    const q = searchParams.get('query');
    const aId = searchParams.get('alert_id');
    const iId = searchParams.get('incident_id');

    if (q || aId || iId) {
      const activeQuery = q || (aId ? `Analyze alert ${aId}` : `Analyze incident ${iId}`);
      setInputQuery(activeQuery);
      handleRunQuery(activeQuery);
    }
    loadHistory();
  }, [searchParams]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Bot className="w-6 h-6 text-purple-400" />
            <span>AI Copilot & Evidence-Grounded RAG Workspace</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Ask questions in natural language. Powered by LangGraph state machine, vector search (pgvector), and playbooks.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => {
              setShowHistory((v) => !v);
              if (!showHistory) loadHistory();
            }}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-purple-500/40 transition-all text-xs font-medium"
          >
            <History className="w-3.5 h-3.5" />
            Investigation History
            {history.length > 0 && (
              <span className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/40 text-[10px] font-mono">
                {history.length}
              </span>
            )}
          </button>
          <button
            onClick={handleSeedDemo}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-medium transition-all shadow-purple-glow disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lightbulb className="w-3.5 h-3.5" />}
            Run Full Demo
          </button>
        </div>
      </div>

      {/* History Panel */}
      {showHistory && (
        <div className="glass-panel p-5 rounded-2xl border border-soc-cardBorder space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" />
              Investigation History
            </h3>
            <button
              onClick={loadHistory}
              disabled={historyLoading}
              className="text-xs text-soc-textMuted hover:text-white inline-flex items-center gap-1 disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${historyLoading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
          {historyLoading ? (
            <div className="flex items-center justify-center py-8 text-soc-textMuted text-xs font-mono">
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
              Loading history...
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-6 text-xs text-soc-textMuted italic">
              No prior investigations. Run a query above to get started.
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {history.map((h) => (
                <button
                  key={h.id}
                  onClick={() => {
                    setInputQuery(h.query);
                    handleRunQuery(h.query);
                  }}
                  className="w-full text-left p-3 rounded-xl bg-soc-sidebar/60 border border-soc-cardBorder hover:border-purple-500/40 transition-all space-y-1"
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-sm text-white font-medium line-clamp-1 leading-snug">
                      {h.query}
                    </p>
                    <span className="text-[10px] font-mono text-soc-textMuted shrink-0 mt-0.5">
                      {Math.round((h.confidence || 0) * 100)}%
                    </span>
                  </div>
                  {h.summary && (
                    <p className="text-xs text-soc-textMuted line-clamp-1 leading-relaxed">
                      {h.summary}
                    </p>
                  )}
                  <div className="text-[10px] font-mono text-soc-textMuted/60 pt-1">
                    {new Date(h.created_at || h.timestamp || Date.now()).toLocaleString()}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Query Bar & Presets */}
      <div className="glass-panel p-5 rounded-2xl border border-soc-cardBorder space-y-4 shadow-purple-glow">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunQuery();
          }}
          className="flex gap-3"
        >
          <div className="relative flex-1">
            <Sparkles className="w-4 h-4 absolute left-3.5 top-3.5 text-purple-400" />
            <input
              type="text"
              placeholder="Ask AI Copilot to analyze alerts, trace attack chains, or retrieve playbooks..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-sm text-white focus:outline-none focus:border-purple-500 font-medium placeholder:text-soc-textMuted"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !inputQuery.trim()}
            className="flex items-center space-x-2 px-5 py-3 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-medium text-sm transition-all disabled:opacity-50 shrink-0"
          >
            <Send className={`w-4 h-4 ${loading ? 'animate-bounce' : ''}`} />
            <span>{loading ? 'Analyzing...' : 'Run RAG Query'}</span>
          </button>
        </form>

        {error && (
          <div className="p-3 rounded-xl border border-rose-800/50 bg-rose-950/20 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <p className="text-xs text-rose-200/80">{error}</p>
          </div>
        )}

        {/* Preset chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-soc-textMuted font-medium">Quick Prompts:</span>
          {presetQueries.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => {
                setInputQuery(preset);
                handleRunQuery(preset);
              }}
              className="px-3 py-1 rounded-lg bg-soc-sidebar border border-soc-cardBorder hover:border-purple-500/50 text-xs text-soc-textMuted hover:text-purple-300 transition-all text-left"
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      {/* Output Panel */}
      {loading && (
        <div className="glass-panel p-12 rounded-2xl border border-soc-cardBorder text-center space-y-3">
          <div className="w-10 h-10 rounded-xl bg-purple-950/60 border border-purple-800/40 text-purple-400 flex items-center justify-center mx-auto animate-pulse">
            <Bot className="w-6 h-6 animate-spin" />
          </div>
          <h3 className="text-base font-semibold text-white">Running LangGraph Investigation Nodes...</h3>
          <p className="text-xs text-soc-textMuted max-w-md mx-auto leading-relaxed">
            Extracting Intent → Querying Vector Database → Filtering Permissions → Mapping MITRE ATT&CK → Generating Evidence Citations
          </p>
        </div>
      )}

      {response && !loading && (
        <div className="space-y-6 animate-fade-in">
          {/* Executive Summary Card */}
          <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h2 className="text-lg font-bold text-white">AI Investigation Findings & Rationale</h2>
              </div>
              <div className="flex items-center space-x-2 gap-2">
                <span className="text-xs text-soc-textMuted font-mono">Investigation:</span>
                <span className="px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-[10px] font-mono text-cyan-400">
                  {response.investigation_id?.slice(0, 14) || 'N/A'}
                </span>
                <span className="text-xs text-soc-textMuted font-mono">Confidence:</span>
                <span className="px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-mono font-bold">
                  {Math.round((response.confidence || 0) * 100)}%
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-2">
              <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Executive Summary</h4>
              <p className="text-sm text-soc-textMain leading-relaxed">{response.summary}</p>
            </div>

            {/* Bullet Findings */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Key Findings</h4>
              <ul className="space-y-1.5 pl-4 list-disc text-xs text-soc-textMuted">
                {response.findings && response.findings.length > 0 ? (
                  response.findings.map((f, i) => <li key={i} className="text-white">{f}</li>)
                ) : (
                  <li className="italic text-soc-textMuted/60">No specific findings extracted.</li>
                )}
              </ul>
            </div>

            {/* Limitations */}
            {response.limitations && response.limitations.length > 0 && (
              <div className="space-y-2 p-3 rounded-xl bg-amber-950/20 border border-amber-800/30">
                <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Analyst Notice (Limitations)
                </h4>
                <ul className="space-y-1 pl-4 list-disc text-xs text-amber-200/80">
                  {response.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Grid: Mapped MITRE & Grounded Citations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* MITRE Techniques */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <Grid className="w-5 h-5 text-rose-400" />
                <span>Mapped MITRE ATT&CK Techniques</span>
              </h3>

              <div className="space-y-3">
                {response.mitre_mappings && response.mitre_mappings.length > 0 ? (
                  response.mitre_mappings.map((m, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1.5 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-400 font-bold">{m.technique_id}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-soc-textMuted">
                            {Math.round((m.confidence || 0) * 100)}%
                          </span>
                          <span className="text-[11px] text-soc-textMuted font-mono">{m.tactic}</span>
                        </div>
                      </div>
                      <div className="font-semibold text-white">{m.technique_name}</div>
                      {m.evidence_snippet && (
                        <p className="text-[11px] text-soc-textMuted font-mono italic bg-soc-card p-2 rounded border border-soc-cardBorder">
                          &quot;{m.evidence_snippet}&quot;
                        </p>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-xs text-soc-textMuted italic">
                    No MITRE ATT&CK technique hypotheses generated for this query.
                  </div>
                )}
              </div>
            </div>

            {/* Cited Evidence RAG Grounding */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <BookOpen className="w-5 h-5 text-cyan-400" />
                <span>Grounded Evidence Citations</span>
              </h3>

              <div className="space-y-3">
                {response.cited_evidence && response.cited_evidence.length > 0 ? (
                  response.cited_evidence.map((cit, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-cyan-300">{cit.title}</span>
                        <span className="text-[10px] font-mono text-emerald-400">
                          Score: {cit.relevance_score ?? (cit as any).score ?? 'N/A'}
                        </span>
                      </div>
                      <p className="text-[11px] text-soc-textMuted line-clamp-3 leading-relaxed">
                        {cit.snippet}
                      </p>
                      <div className="text-[10px] font-mono text-soc-textMuted pt-0.5">
                        Source: {cit.source_type} ({cit.source_id})
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-xs text-soc-textMuted italic">
                    No cited evidence sources returned.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Recommendations */}
          {response.recommendations && response.recommendations.length > 0 && (
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <Zap className="w-5 h-5 text-amber-400" />
                <span>Investigative & Response Recommendations</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {response.recommendations.map((rec, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border text-xs space-y-2 ${
                      rec.category === 'response'
                        ? 'bg-rose-950/20 border-rose-800/40'
                        : 'bg-cyan-950/20 border-cyan-800/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="font-semibold text-sm text-white leading-snug">{rec.title}</span>
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            rec.category === 'response'
                              ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                              : 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/40'
                          }`}
                        >
                          {rec.category}
                        </span>
                        {rec.requires_approval && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-mono">
                            Approval
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-soc-textMuted leading-relaxed">{rec.description}</p>
                    {rec.priority && (
                      <div className="text-[10px] font-mono text-soc-textMuted pt-0.5">
                        Priority: <span className="uppercase">{rec.priority}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Analyst Feedback Section */}
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-soc-textMuted font-medium">
              Was this AI investigation helpful to your workflow?
            </span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => handleFeedback('useful')}
                disabled={submittingFeedback || feedbackGiven !== null}
                className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg border transition-all ${
                  feedbackGiven === 'useful'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted hover:text-white disabled:opacity-50'
                }`}
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Useful</span>
              </button>
              <button
                onClick={() => handleFeedback('incomplete')}
                disabled={submittingFeedback || feedbackGiven !== null}
                className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg border transition-all ${
                  feedbackGiven === 'incomplete'
                    ? 'bg-amber-950 text-amber-300 border-amber-700'
                    : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted hover:text-white disabled:opacity-50'
                }`}
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>Needs Improvement</span>
              </button>
              {feedbackGiven && (
                <span className="text-[11px] font-mono text-emerald-400 inline-flex items-center gap-1 pl-2">
                  <CheckCircle2 className="w-3 h-3" />
                  Logged
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function CopilotPage() {
  return (
    <div className="space-y-6">
      <Suspense
        fallback={
          <div className="glass-panel p-8 text-center text-soc-textMuted font-mono text-xs">
            Loading AI Copilot Workspace...
          </div>
        }
      >
        <CopilotContent />
      </Suspense>
    </div>
  );
}
