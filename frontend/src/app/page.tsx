'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  Activity,
  Flame,
  Clock,
  ArrowUpRight,
  Bot,
  Zap,
  AlertTriangle,
  RefreshCw
} from 'lucide-react';
import StatCard from '@/components/StatCard';
import SeverityBadge from '@/components/SeverityBadge';
import { getDashboardStats, getAlerts, triggerSyntheticScenario, AlertItem } from '@/lib/api';

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, alertsRes] = await Promise.all([
        getDashboardStats(),
        getAlerts(),
      ]);
      setStats(statsRes);
      setAlerts(alertsRes.items || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load dashboard data');
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSimulate = async () => {
    setSimulating(true);
    setError(null);
    try {
      await triggerSyntheticScenario();
      await fetchData();
    } catch (e: any) {
      setError(e?.message || 'Failed to inject scenario');
      console.error(e);
    } finally {
      setSimulating(false);
    }
  };

  const sev = stats?.alerts_by_severity || { critical: 0, high: 0, medium: 0, low: 0 };
  const sevTotal = sev.critical + sev.high + sev.medium + sev.low || 1;
  const sevPct = (val: number) => Math.max(0, Math.round((val / sevTotal) * 1000) / 10);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Banner Header */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder bg-gradient-to-r from-soc-card via-soc-sidebar to-soc-card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border flex items-center gap-1 ${
              stats?.critical_incidents > 0 || sev.critical > 0
                ? 'bg-rose-950 text-rose-300 border-rose-800/50'
                : 'bg-amber-950 text-amber-300 border-amber-800/50'
            }`}>
              <span className={`w-2 h-2 rounded-full ${stats?.critical_incidents > 0 || sev.critical > 0 ? 'bg-rose-500 animate-ping' : 'bg-amber-500 animate-pulse'}`} />
              THREAT LEVEL: {loading ? 'LOADING...' : (stats?.threat_level || 'NOMINAL')}
            </span>
          </div>
          <p className="text-sm text-soc-textMuted mt-1">
            Real-time multi-source security event correlation & AI-guided evidence triage
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchData}
            className="p-2.5 rounded-xl bg-soc-card border border-soc-cardBorder text-soc-textMuted hover:text-white transition-all"
            title="Refresh Data"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={handleSimulate}
            disabled={simulating}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-cyan-glow transition-all active:scale-95"
          >
            <Zap className={`w-4 h-4 ${simulating ? 'animate-spin' : ''}`} />
            <span>{simulating ? 'Simulating...' : 'Ingest Attack Scenario'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/60 text-rose-300 text-sm">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Normalized Events"
          value={loading ? '—' : (stats?.total_events ? stats.total_events.toLocaleString() : '0')}
          subtitle={loading ? 'Loading telemetry...' : `${Math.floor((stats?.total_events || 0) / 10)} events/min estimate`}
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Active Alerts"
          value={loading ? '—' : (stats?.total_alerts || '0')}
          subtitle={loading ? '' : `${sev.critical} Critical • ${sev.high} High`}
          icon={AlertTriangle}
          color="amber"
        />
        <StatCard
          title="Correlated Incidents"
          value={loading ? '—' : (stats?.open_incidents || '0')}
          subtitle={loading ? '' : `${stats?.critical_incidents || 0} Requiring Urgent Action`}
          icon={Flame}
          color="rose"
        />
        <StatCard
          title="MTTR (Mean Response)"
          value={loading ? '—' : `${stats?.mean_time_to_respond_mins || '0.0'} min`}
          subtitle={loading ? '' : 'RAG vector retrieval active'}
          icon={Clock}
          color="emerald"
        />
      </div>

      {/* Main Grid: Alert Severity Breakdown & Live Alerts Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity & Telemetry Overview */}
        <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-6">
          <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span>Alert Severity Breakdown</span>
          </h2>

          {loading ? (
            <div className="space-y-4">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="animate-pulse space-y-1">
                  <div className="h-3 bg-soc-card rounded w-1/3" />
                  <div className="h-2 bg-soc-card rounded-full w-full" />
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span className="text-rose-400">Critical ({sev.critical})</span>
                  <span className="text-soc-textMuted">{sevPct(sev.critical)}%</span>
                </div>
                <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                  <div className="bg-rose-500 h-2 rounded-full transition-all" style={{ width: `${sevPct(sev.critical)}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span className="text-amber-400">High ({sev.high})</span>
                  <span className="text-soc-textMuted">{sevPct(sev.high)}%</span>
                </div>
                <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                  <div className="bg-amber-500 h-2 rounded-full transition-all" style={{ width: `${sevPct(sev.high)}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span className="text-cyan-400">Medium ({sev.medium})</span>
                  <span className="text-soc-textMuted">{sevPct(sev.medium)}%</span>
                </div>
                <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                  <div className="bg-cyan-500 h-2 rounded-full transition-all" style={{ width: `${sevPct(sev.medium)}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs font-medium mb-1">
                  <span className="text-emerald-400">Low ({sev.low})</span>
                  <span className="text-soc-textMuted">{sevPct(sev.low)}%</span>
                </div>
                <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                  <div className="bg-emerald-500 h-2 rounded-full transition-all" style={{ width: `${sevPct(sev.low)}%` }} />
                </div>
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-soc-cardBorder space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">Correlation Engine Status</span>
              <span className="text-emerald-400 font-mono">Active</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">RAG Vector Storage</span>
              <span className="text-cyan-400 font-mono">pgvector Ready</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">MITRE Mapping Service</span>
              <span className="text-purple-400 font-mono">ATT&CK v14 Synced</span>
            </div>
          </div>

          <Link
            href="/copilot"
            className="flex items-center justify-center space-x-2 w-full py-2.5 rounded-xl bg-purple-950/60 text-purple-300 border border-purple-800/40 hover:bg-purple-900/60 font-medium text-xs transition-all"
          >
            <Bot className="w-4 h-4 text-purple-400" />
            <span>Ask AI Copilot for Investigation</span>
          </Link>
        </div>

        {/* Live Urgent Alerts Queue */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <span>Urgent Security Alerts Queue</span>
            </h2>
            <Link
              href="/alerts"
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
            >
              <span>View All Alerts ({alerts.length})</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {loading ? (
            <div className="divide-y divide-soc-cardBorder">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="py-4 animate-pulse">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2 flex-1">
                      <div className="flex items-center space-x-2">
                        <div className="w-14 h-5 bg-soc-card rounded" />
                        <div className="h-4 bg-soc-card rounded w-1/2" />
                      </div>
                      <div className="h-3 bg-soc-card rounded w-3/4" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : alerts.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-soc-textMuted text-sm">No alerts in queue. Click <strong>&quot;Ingest Attack Scenario&quot;</strong> to generate synthetic test data.</p>
            </div>
          ) : (
            <div className="divide-y divide-soc-cardBorder">
              {alerts.slice(0, 4).map((alert) => (
                <div key={alert.id} className="py-3.5 flex items-start justify-between gap-4 group">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2.5">
                      <SeverityBadge severity={alert.severity} />
                      <span className="font-semibold text-sm text-white group-hover:text-cyan-400 transition-colors">
                        {alert.title}
                      </span>
                    </div>
                    <p className="text-xs text-soc-textMuted line-clamp-1">{alert.description}</p>
                    <div className="flex items-center space-x-3 text-[11px] font-mono text-soc-textMuted">
                      <span>Source: <strong className="text-soc-textMain">{alert.source.toUpperCase()}</strong></span>
                      <span>Asset: <strong className="text-cyan-400">{alert.asset_id || 'N/A'}</strong></span>
                      <span>Status: <strong className="text-amber-400">{alert.status}</strong></span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <Link
                      href={`/copilot?alert_id=${alert.id}&query=${encodeURIComponent(`Analyze alert: ${alert.title}`)}`}
                      className="p-2 rounded-lg bg-soc-card border border-soc-cardBorder text-cyan-400 hover:bg-cyan-950/40 text-xs font-medium flex items-center space-x-1"
                      title="Investigate with AI Copilot"
                    >
                      <Bot className="w-4 h-4" />
                      <span className="hidden sm:inline">Investigate</span>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
