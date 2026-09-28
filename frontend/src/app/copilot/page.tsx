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
  Zap
} from 'lucide-react';
import { queryCopilot, CopilotResponse } from '@/lib/api';

function CopilotContent() {
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get('query') || '';

  const [inputQuery, setInputQuery] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<CopilotResponse | null>(null);
  const [feedbackGiven, setFeedbackGiven] = useState<string | null>(null);

  const presetQueries = [
    'Explain LSASS memory dump alert on WORKSTATION-089 and give containment steps.',
    'What evidence links the phishing email to the outbound C2 connection?',
    'Summarize threat actor tactics and MITRE ATT&CK techniques observed.',
    'Recommend automated response actions for credential dumping.',
  ];

  const handleRunQuery = async (queryToRun?: string) => {
    const targetQuery = queryToRun || inputQuery;
    if (!targetQuery.trim()) return;

    setLoading(true);
    setFeedbackGiven(null);
    try {
      const res = await queryCopilot(targetQuery);
      setResponse(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialQuery) {
      handleRunQuery(initialQuery);
    }
  }, [initialQuery]);

  return (
    <div className="space-y-6">
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
          <p className="text-xs text-soc-textMuted">
            Extracting Intent → Querying Vector Database → Filtering Permissions → Mapping MITRE ATT&CK → Generating Evidence Citations
          </p>
        </div>
      )}

      {response && !loading && (
        <div className="space-y-6 animate-fade-in">
          {/* Executive Summary Card */}
          <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h2 className="text-lg font-bold text-white">AI Investigation Findings & Rationale</h2>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-xs text-soc-textMuted font-mono">Confidence Level:</span>
                <span className="px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-mono font-bold">
                  {Math.round(response.confidence * 100)}%
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
                {response.findings.map((f, i) => (
                  <li key={i} className="text-white">{f}</li>
                ))}
              </ul>
            </div>
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
                {response.mitre_mappings.map((m, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-rose-400 font-bold">{m.technique_id}</span>
                      <span className="text-[11px] text-soc-textMuted font-mono">{m.tactic}</span>
                    </div>
                    <div className="font-semibold text-white">{m.technique_name}</div>
                    <p className="text-[11px] text-soc-textMuted font-mono italic bg-soc-card p-2 rounded border border-soc-cardBorder">
                      "{m.evidence_snippet}"
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Cited Evidence RAG Grounding */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <BookOpen className="w-5 h-5 text-cyan-400" />
                <span>Grounded Evidence Citations</span>
              </h3>

              <div className="space-y-3">
                {response.cited_evidence.map((cit, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-cyan-300">{cit.title}</span>
                      <span className="text-[10px] font-mono text-emerald-400">Score: {cit.relevance_score}</span>
                    </div>
                    <p className="text-[11px] text-soc-textMuted">{cit.snippet}</p>
                    <div className="text-[10px] font-mono text-soc-textMuted pt-0.5">
                      Source: {cit.source_type} ({cit.source_id})
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Analyst Feedback Section */}
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder flex items-center justify-between text-xs">
            <span className="text-soc-textMuted font-medium">Was this AI investigation helpful to your workflow?</span>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setFeedbackGiven('useful')}
                className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg border transition-all ${
                  feedbackGiven === 'useful'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted hover:text-white'
                }`}
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Useful</span>
              </button>
              <button
                onClick={() => setFeedbackGiven('incomplete')}
                className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg border transition-all ${
                  feedbackGiven === 'incomplete'
                    ? 'bg-amber-950 text-amber-300 border-amber-700'
                    : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted hover:text-white'
                }`}
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>Needs Improvement</span>
              </button>
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
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Bot className="w-6 h-6 text-purple-400" />
          <span>AI Copilot & Evidence-Grounded RAG Workspace</span>
        </h1>
        <p className="text-sm text-soc-textMuted mt-1">
          Ask questions in natural language. Powered by LangGraph state machine, vector search (pgvector), and playbooks.
        </p>
      </div>

      <Suspense fallback={
        <div className="glass-panel p-8 text-center text-soc-textMuted font-mono text-xs">
          Loading AI Copilot Workspace...
        </div>
      }>
        <CopilotContent />
      </Suspense>
    </div>
  );
}
