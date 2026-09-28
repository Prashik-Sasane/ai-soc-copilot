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
  Lock
} from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import { getIncidents, IncidentItem } from '@/lib/api';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [activeIncident, setActiveIncident] = useState<IncidentItem | null>(null);
  const [executedActions, setExecutedActions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const res = await getIncidents();
        setIncidents(res.items || []);
        if (res.items && res.items.length > 0) {
          setActiveIncident(res.items[0]);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

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
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Flame className="w-6 h-6 text-rose-500" />
          <span>Incident Workspace & Investigation Timeline</span>
        </h1>
        <p className="text-sm text-soc-textMuted mt-1">
          Correlated multi-stage security incident response, event timeline, MITRE technique tagging, and approved analyst actions.
        </p>
      </div>

      {activeIncident && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Left Panel: Incident Overview & Interactive Timeline */}
          <div className="lg:col-span-2 space-y-6">
            {/* Header Card */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <SeverityBadge severity={activeIncident.severity} />
                    <span className="px-2.5 py-0.5 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800/40 text-xs font-mono">
                      {activeIncident.id}
                    </span>
                    <span className="px-2 py-0.5 rounded-md bg-soc-card border border-soc-cardBorder text-xs text-soc-textMuted font-mono">
                      Status: {activeIncident.status.toUpperCase()}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-white">{activeIncident.title}</h2>
                </div>

                <Link
                  href={`/copilot?incident_id=${activeIncident.id}`}
                  className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-purple-950/60 text-purple-300 border border-purple-800/40 hover:bg-purple-900/60 text-xs font-medium transition-all shadow-purple-glow"
                >
                  <Bot className="w-4 h-4 text-purple-400" />
                  <span>Investigate with AI Copilot</span>
                </Link>
              </div>

              <p className="text-xs text-soc-textMuted leading-relaxed bg-soc-sidebar/60 p-3.5 rounded-xl border border-soc-cardBorder">
                {activeIncident.description}
              </p>

              {/* Technique tags */}
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
            </div>

            {/* Visual Timeline Stream */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-6">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <Clock className="w-5 h-5 text-cyan-400" />
                <span>Multi-Stage Attack Chain Timeline</span>
              </h3>

              <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-amber-500 before:to-rose-500">
                {activeIncident.timeline_json.map((item, index) => (
                  <div key={index} className="relative group">
                    {/* Node marker */}
                    <span className={`absolute -left-6 top-1 w-4 h-4 rounded-full border-2 bg-soc-card ${
                      item.severity === 'critical'
                        ? 'border-rose-500 shadow-rose-glow'
                        : item.severity === 'high'
                        ? 'border-amber-500 shadow-amber-glow'
                        : 'border-cyan-500 shadow-cyan-glow'
                    }`} />

                    <div className="p-4 rounded-xl bg-soc-sidebar/80 border border-soc-cardBorder group-hover:border-cyan-500/40 transition-all space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm text-white">{item.title}</span>
                        <span className="text-[11px] font-mono text-soc-textMuted">
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-xs text-soc-textMuted">{item.description}</p>
                      <div className="flex items-center space-x-3 text-[11px] font-mono pt-1">
                        <span className="text-soc-textMuted">Source: <strong className="text-cyan-400">{item.source}</strong></span>
                        <span className="text-soc-textMuted">Event: <strong className="text-amber-400">{item.event_type}</strong></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Sidebar: Analyst Response Actions & Key Indicators */}
          <div className="space-y-6">
            {/* Analyst Response Actions Panel */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <Zap className="w-5 h-5 text-amber-400" />
                <span>Analyst Response Playbook</span>
              </h3>

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
            </div>

            {/* Target Asset & Associated IOCs */}
            <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <Lock className="w-5 h-5 text-cyan-400" />
                <span>Indicators of Compromise</span>
              </h3>

              <div className="space-y-2.5">
                <div className="p-3 rounded-xl bg-soc-sidebar border border-soc-cardBorder flex items-center justify-between text-xs">
                  <div>
                    <span className="text-soc-textMuted font-mono text-[11px]">IP C2 Node</span>
                    <div className="font-mono text-cyan-400 font-bold">198.51.100.44</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/40 text-[11px] font-mono">
                    High Risk
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-soc-sidebar border border-soc-cardBorder flex items-center justify-between text-xs">
                  <div>
                    <span className="text-soc-textMuted font-mono text-[11px]">Domain</span>
                    <div className="font-mono text-cyan-400 font-bold">c2-command-node.ru</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/40 text-[11px] font-mono">
                    Critical
                  </span>
                </div>
              </div>

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
  );
}
