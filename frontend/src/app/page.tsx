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
  CheckCircle,
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

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, alertsRes] = await Promise.all([
        getDashboardStats(),
        getAlerts(),
      ]);
      setStats(statsRes);
      setAlerts(alertsRes.items || []);
    } catch (e) {
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
    try {
      await triggerSyntheticScenario();
      await fetchData();
    } catch (e) {
      console.error(e);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Banner Header */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder bg-gradient-to-r from-soc-card via-soc-sidebar to-soc-card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-rose-950 text-rose-300 border border-rose-800/50 flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
              THREAT LEVEL: ELEVATED
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

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Normalized Events"
          value={stats?.total_events ? stats.total_events.toLocaleString() : '14,250'}
          subtitle="+1,420 events/min velocity"
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Active Alerts"
          value={stats?.total_alerts || '24'}
          subtitle="2 Critical, 7 High"
          icon={AlertTriangle}
          color="amber"
        />
        <StatCard
          title="Correlated Incidents"
          value={stats?.open_incidents || '3'}
          subtitle="1 Requiring Urgent Action"
          icon={Flame}
          color="rose"
        />
        <StatCard
          title="MTTR (Mean Response)"
          value={`${stats?.mean_time_to_respond_mins || '14.2'} min`}
          subtitle="-440ms RAG Latency"
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

          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-xs font-medium mb-1">
                <span className="text-rose-400">Critical (2)</span>
                <span className="text-soc-textMuted">8.3%</span>
              </div>
              <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                <div className="bg-rose-500 h-2 rounded-full w-[8.3%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-medium mb-1">
                <span className="text-amber-400">High (7)</span>
                <span className="text-soc-textMuted">29.1%</span>
              </div>
              <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                <div className="bg-amber-500 h-2 rounded-full w-[29.1%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-medium mb-1">
                <span className="text-cyan-400">Medium (10)</span>
                <span className="text-soc-textMuted">41.6%</span>
              </div>
              <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                <div className="bg-cyan-500 h-2 rounded-full w-[41.6%]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-medium mb-1">
                <span className="text-emerald-400">Low (5)</span>
                <span className="text-soc-textMuted">21.0%</span>
              </div>
              <div className="w-full bg-soc-card rounded-full h-2 overflow-hidden border border-soc-cardBorder">
                <div className="bg-emerald-500 h-2 rounded-full w-[21%]" />
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-soc-cardBorder space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">Correlation Engine Status</span>
              <span className="text-emerald-400 font-mono">Active (F1: 1.0)</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">RAG Vector Storage</span>
              <span className="text-cyan-400 font-mono">pgvector Ready</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-soc-textMuted">MITRE Mapping Service</span>
              <span className="text-purple-400 font-mono">v14 ATT&CK Sync</span>
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
                    href={`/copilot?query=${encodeURIComponent(`Analyze alert: ${alert.title}`)}`}
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
        </div>
      </div>
    </div>
  );
}
