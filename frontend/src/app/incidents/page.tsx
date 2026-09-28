'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Flame,
  Clock,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Bot,
  Zap,
  CheckCircle2,
  AlertOctagon,
  FileText,
  Lock,
  List,
  RefreshCw,
  Loader2,
  AlertCircle,
  Activity,
  Link2
} from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import {
  getIncidents,
  getIndicators,
  triggerCorrelation,
  seedDemoScenario,
  IncidentItem,
  IndicatorItem
} from '@/lib/api';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [indicators, setIndicators] = useState<IndicatorItem[]>([]);
  const [activeIncident, setActiveIncident] = useState<IncidentItem | null>(null);
  const [executedActions, setExecutedActions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [incRes, indRes] = await Promise.all([
        getIncidents(),
        getIndicators(undefined, undefined, 30),
      ]);
      const items = incRes.items || [];
      setIncidents(items);
      setIndicators(indRes || []);
      if (items.length > 0) {
        setActiveIncident((current) => {
          if (current && items.find((i) => i.id === current.id)) return current;
          return items[0];
        });
      } else {
        setActiveIncident(null);
      }
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSeed = async () => {
    setSeeding(true);
    setError(null);
    try {
      await seedDemoScenario();
      try {
        await triggerCorrelation();
      } catch {}
      await loadData();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to seed scenario');
    } finally {
      setSeeding(false);
    }
  };

  const handleCorrelate = async () => {
    setCorrelating(true);
    setError(null);
    try {
      await triggerCorrelation();
      await loadData();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to run correlation');
    } finally {
      setCorrelating(false);
    }
  };

  const handleExecuteAction = (actionTitle: string) => {
    if (!executedActions.includes(actionTitle)) {
      setExecutedActions([...executedActions, actionTitle]);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex items-center space-x-3 text-cyan-400 font-mono text-sm">
          <span className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
          <span>Loading Correlated Incidents...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Flame className="w-6 h-6 text-rose-500" />
            <span>Incident Workspace & Investigation Timeline</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Correlated multi-stage security incident response, event timeline, MITRE technique tagging, and approved analyst actions.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={loadData}
            disabled={loading || seeding || correlating}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-rose-500/40 transition-all text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleCorrelate}
            disabled={correlating || seeding || loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-950/60 text-amber-300 border border-amber-800/40 hover:bg-amber-900/60 text-xs font-medium transition-all disabled:opacity-50"
          >
            {correlating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Link2 className="w-3.5 h-3.5" />}
            {correlating ? 'Correlating...' : 'Run Correlation'}
          </button>
          <button
            onClick={handleSeed}
            disabled={seeding || correlating || loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-xs font-medium transition-all shadow-rose-glow disabled:opacity-50"
          >
            {seeding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
            {seeding ? 'Seeding...' : 'Seed Demo Attack'}
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-panel p-4 rounded-2xl border border-rose-800/50 bg-rose-950/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-rose-300 font-semibold">Error</p>
            <p className="text-xs text-rose-200/70 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {incidents.length === 0 ? (
        <div className="glass-panel p-12 rounded-2xl border border-soc-cardBorder text-center space-y-5">
          <div className="w-16 h-16 rounded-2xl bg-soc-sidebar border border-soc-cardBorder flex items-center justify-center mx-auto">
            <Flame className="w-8 h-8 text-rose-400/70" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">No Incidents Detected Yet</h3>
            <p className="text-sm text-soc-textMuted mt-1 max-w-md mx-auto leading-relaxed">
              The correlation engine analyzes alerts to find multi-stage attack patterns and group them into incidents.
              Seed a synthetic multi-stage attack scenario to walk through the full incident response workflow.
            </p>
          </div>
          <button
            onClick={handleSeed}
            disabled={seeding}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-sm font-medium transition-all shadow-rose-glow disabled:opacity-50 inline-flex items-center gap-2"
          >
            {seeding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            {seeding ? 'Seeding Attack Scenario...' : 'Seed Demo Attack & Create Incident'}
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Incident List Sidebar */}
          <div className="lg:col-span-1 space-y-3">
            <div className="flex items-center justify-between px-1">
              <h3 className="text-xs font-semibold text-soc-textMuted uppercase tracking-wider flex items-center gap-1.5">
                <List className="w-3.5 h-3.5" />
                Incidents Queue
              </h3>
              <span className="px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-xs font-mono text-rose-400">
                {incidents.length} Total
              </span>
            </div>
            <div className="space-y-2">
              {incidents.map((inc) => {
                const isActive = activeIncident?.id === inc.id;
                return (
                  <button
                    key={inc.id}
                    onClick={() => {
                      setActiveIncident(inc);
                      setExecutedActions([]);
                    }}
                    className={`w-full text-left p-4 rounded-2xl border transition-all space-y-2 ${
                      isActive
                        ? 'bg-soc-card/80 border-rose-500/40 shadow-rose-glow'
                        : 'bg-soc-sidebar/60 border-soc-cardBorder hover:border-soc-cardBorder/80 hover:bg-soc-sidebar'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <SeverityBadge severity={inc.severity} />
                      <span className="text-[10px] font-mono text-soc-textMuted shrink-0 mt-0.5">
                        {inc.id}
                      </span>
                    </div>
                    <h4 className="font-semibold text-sm text-white leading-snug line-clamp-2">
                      {inc.title}
                    </h4>
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-soc-card border border-soc-cardBorder text-soc-textMuted">
                        {inc.status}
                      </span>
                      {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                        <span className="text-[10px] font-mono text-rose-400">
                          {inc.mitre_techniques.length} TTPs
                        </span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Main Detail Panel */}
          {activeIncident && (
            <div className="lg:col-span-2 space-y-6">
              {/* Header Card */}
              <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
                <div className="flex items-start justify-between flex-wrap gap-4">
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={activeIncident.severity} />
                      <span className="px-2.5 py-0.5 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800/40 text-xs font-mono">
                        {activeIncident.id}
                      </span>
                      <span className="px-2 py-0.5 rounded-md bg-soc-card border border-soc-cardBorder text-xs text-soc-textMuted font-mono">
                        Status: {activeIncident.status.toUpperCase()}
                      </span>
                    </div>
                    <h2 className="text-xl font-bold text-white leading-tight">{activeIncident.title}</h2>
                  </div>

                  <Link
                    href={`/copilot?incident_id=${activeIncident.id}`}
                    className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-purple-950/60 text-purple-300 border border-purple-800/40 hover:bg-purple-900/60 text-xs font-medium transition-all shadow-purple-glow shrink-0"
                  >
                    <Bot className="w-4 h-4 text-purple-400" />
                    <span>Investigate with AI Copilot</span>
                  </Link>
                </div>

                {activeIncident.description ? (
                  <p className="text-xs text-soc-textMuted leading-relaxed bg-soc-sidebar/60 p-3.5 rounded-xl border border-soc-cardBorder">
                    {activeIncident.description}
                  </p>
                ) : (
                  <p className="text-xs text-soc-textMuted/70 italic bg-soc-sidebar/40 p-3.5 rounded-xl border border-dashed border-soc-cardBorder/60">
                    No description provided for this incident.
                  </p>
                )}

                {/* Technique tags */}
                {activeIncident.mitre_techniques && activeIncident.mitre_techniques.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-2 pt-2">
                    <span className="text-xs text-soc-textMuted font-medium">Mapped MITRE Techniques:</span>
                    {activeIncident.mitre_techniques.map((tech) => (
                      <span
                        key={tech}
                        className="px-2.5 py-1 rounded-lg bg-rose-950/50 text-rose-300 border border-rose-800/40 text-xs font-mono font-semibold"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 pt-2">
                    <span className="text-xs text-soc-textMuted font-medium">Mapped MITRE Techniques:</span>
                    <span className="text-xs text-soc-textMuted/60 italic">None tagged yet.</span>
                  </div>
                )}
              </div>

              {/* Visual Timeline Stream */}
              <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
                <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                  <Clock className="w-5 h-5 text-cyan-400" />
                  <span>Multi-Stage Attack Chain Timeline</span>
                </h3>

                {activeIncident.timeline_json && activeIncident.timeline_json.length > 0 ? (
                  <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-amber-500 before:to-rose-500">
                    {activeIncident.timeline_json.map((item, index) => (
                      <div key={index} className="relative group">
                        <span
                          className={`absolute -left-6 top-1 w-4 h-4 rounded-full border-2 bg-soc-card ${
                            item.severity === 'critical'
                              ? 'border-rose-500 shadow-rose-glow'
                              : item.severity === 'high'
                              ? 'border-amber-500 shadow-amber-glow'
                              : 'border-cyan-500 shadow-cyan-glow'
                          }`}
                        />
                        <div className="p-4 rounded-xl bg-soc-sidebar/80 border border-soc-cardBorder group-hover:border-cyan-500/40 transition-all space-y-1.5">
                          <div className="flex items-center justify-between flex-wrap gap-2">
                            <span className="font-semibold text-sm text-white">{item.title}</span>
                            <span className="text-[11px] font-mono text-soc-textMuted">
                              {new Date(item.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-xs text-soc-textMuted leading-relaxed">{item.description}</p>
                          <div className="flex items-center gap-3 text-[11px] font-mono pt-1 flex-wrap">
                            <span className="text-soc-textMuted">
                              Source: <strong className="text-cyan-400">{item.source}</strong>
                            </span>
                            <span className="text-soc-textMuted">
                              Event: <strong className="text-amber-400">{item.event_type}</strong>
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-10">
                    <p className="text-sm text-soc-textMuted italic">
                      No timeline events available for this incident.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Right Sidebar: Response + IOCs */}
          {activeIncident && (
            <div className="lg:col-span-3 lg:grid lg:grid-cols-3 lg:gap-6 space-y-6 lg:space-y-0">
              <div className="lg:col-span-2 space-y-6">
                {/* Analyst Response Actions Panel */}
                <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
                  <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                    <Zap className="w-5 h-5 text-amber-400" />
                    <span>Analyst Response Playbook</span>
                  </h3>

                  {activeIncident.recommendations_json && activeIncident.recommendations_json.length > 0 ? (
                    <div className="space-y-3">
                      {activeIncident.recommendations_json.map((rec, idx) => {
                        const isExecuted = executedActions.includes(rec.title);
                        return (
                          <div
                            key={idx}
                            className={`p-3.5 rounded-xl border text-xs space-y-2 transition-all ${
                              isExecuted
                                ? 'bg-emerald-950/40 border-emerald-700/50 text-emerald-200'
                                : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMain'
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <span className="font-semibold text-white">{rec.title}</span>
                              {rec.requires_approval && !isExecuted && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-mono shrink-0">
                                  Approval Req
                                </span>
                              )}
                              {rec.category && (
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono shrink-0 ${
                                    rec.category === 'response'
                                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/40'
                                      : 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/40'
                                  }`}
                                >
                                  {rec.category}
                                </span>
                              )}
                            </div>
                            <p className="text-[11px] text-soc-textMuted leading-relaxed">{rec.description}</p>

                            <div className="pt-2 flex justify-end">
                              {isExecuted ? (
                                <div className="flex items-center space-x-1 text-emerald-400 font-semibold text-xs">
                                  <CheckCircle2 className="w-4 h-4" />
                                  <span>Executed & Logged</span>
                                </div>
                              ) : (
                                <button
                                  onClick={() => handleExecuteAction(rec.title)}
                                  className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-medium text-xs shadow-rose-glow transition-all"
                                >
                                  Execute Containment
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-center py-10">
                      <p className="text-sm text-soc-textMuted italic">
                        No response playbook recommendations yet. Ask AI Copilot to generate them.
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* IOCs */}
              <div className="space-y-6">
                <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
                  <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                    <Lock className="w-5 h-5 text-cyan-400" />
                    <span>Indicators of Compromise</span>
                  </h3>

                  {indicators.length > 0 ? (
                    <div className="space-y-2.5">
                      {indicators.slice(0, 8).map((ind) => {
                        const severity =
                          ind.risk_level === 'critical' || ind.risk_level === 'high' ? 'high' : ind.risk_level === 'medium' ? 'med' : 'low';
                        const badgeCls =
                          severity === 'high'
                            ? 'bg-rose-950 text-rose-300 border-rose-800/40'
                            : severity === 'med'
                            ? 'bg-amber-950 text-amber-300 border-amber-800/40'
                            : 'bg-cyan-950 text-cyan-300 border-cyan-800/40';
                        return (
                          <Link
                            key={ind.id}
                            href={`/indicators`}
                            className="block p-3 rounded-xl bg-soc-sidebar border border-soc-cardBorder hover:border-cyan-500/40 transition-all"
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="text-soc-textMuted font-mono text-[11px] uppercase">
                                  {ind.indicator_type}
                                </span>
                                <div className={`font-mono font-bold text-xs mt-0.5 break-all ${
                                  ind.risk_level === 'critical' || ind.risk_level === 'high'
                                    ? 'text-rose-400'
                                    : ind.risk_level === 'medium'
                                    ? 'text-amber-400'
                                    : 'text-cyan-400'
                                }`}>
                                  {ind.indicator_value.length > 24
                                    ? ind.indicator_value.slice(0, 24) + '...'
                                    : ind.indicator_value}
                                </div>
                              </div>
                              <span className={`px-2 py-0.5 rounded border text-[11px] font-mono shrink-0 ${badgeCls}`}>
                                {ind.reputation_score}/100
                              </span>
                            </div>
                          </Link>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-xs text-soc-textMuted italic">
                        No enriched indicators yet.
                      </p>
                    </div>
                  )}

                  <Link
                    href="/indicators"
                    className="block text-center text-xs text-cyan-400 hover:text-cyan-300 font-medium pt-2"
                  >
                    Perform Threat Intel Enrichment →
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
