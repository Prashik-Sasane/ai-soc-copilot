'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  Bot,
  Eye,
  X,
  ExternalLink,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import { getAlerts, updateAlertStatus, AlertItem } from '@/lib/api';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchAlertsData = async () => {
    setLoading(true);
    try {
      const res = await getAlerts();
      setAlerts(res.items || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlertsData();
  }, []);

  const handleStatusChange = async (alertId: string, newStatus: string) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus as any } : a))
      );
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert({ ...selectedAlert, status: newStatus as any });
      }
    } catch (e) {
      console.error(e);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false;
    if (filterSource !== 'all' && a.source !== filterSource) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.title.toLowerCase().includes(q) ||
        (a.asset_id && a.asset_id.toLowerCase().includes(q)) ||
        (a.description && a.description.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <AlertTriangle className="w-6 h-6 text-amber-400" />
            <span>Alert Management & Triage Queue</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Review normalized security alerts, evaluate correlation context, and trigger AI copilot triage.
          </p>
        </div>

        <button
          onClick={fetchAlertsData}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-soc-card border border-soc-cardBorder text-soc-textMuted hover:text-white transition-all text-xs font-medium self-start"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-3 text-soc-textMuted" />
          <input
            type="text"
            placeholder="Search by title, asset, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-3 w-full md:w-auto">
          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-soc-textMuted" />
            <span className="text-xs text-soc-textMuted font-medium">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-soc-sidebar border border-soc-cardBorder text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs text-soc-textMuted font-medium">Source:</span>
            <select
              value={filterSource}
              onChange={(e) => setFilterSource(e.target.value)}
              className="bg-soc-sidebar border border-soc-cardBorder text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Sources</option>
              <option value="edr">EDR</option>
              <option value="firewall">Firewall</option>
              <option value="identity">Identity</option>
              <option value="dns">DNS</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="glass-panel rounded-2xl border border-soc-cardBorder overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-soc-sidebar/60 border-b border-soc-cardBorder text-[11px] font-semibold uppercase tracking-wider text-soc-textMuted">
                <th className="py-3 px-4">Severity / Risk</th>
                <th className="py-3 px-4">Alert Title</th>
                <th className="py-3 px-4">Asset / Host</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-cardBorder text-xs">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-soc-textMuted">
                    No alerts yet. Waiting for ingested events and detection rules — this queue does not invent live alerts.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-soc-hover/50 transition-colors">
                    <td className="py-3 px-4">
                      <SeverityBadge severity={alert.severity} />
                      {typeof alert.risk_score === 'number' && (
                        <div
                          className="mt-1 text-[10px] font-mono text-soc-textMuted"
                          title="Heuristic risk score, not a probability of compromise"
                        >
                          {'Risk ' + alert.risk_score + '/100'}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-medium text-white">
                        {alert.title}
                        {/* {alert.is_simulated === 'true' && (
                          <span className="ml-2 text-[10px] font-mono text-amber-300">SIMULATED</span>
                        )} */}
                      </div>
                      <div className="text-[11px] text-soc-textMuted line-clamp-1">{alert.description}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400">
                      {alert.asset_id || 'N/A'}
                    </td>
                    <td className="py-3 px-4 font-mono uppercase text-soc-textMuted">
                      {alert.source}
                    </td>
                    <td className="py-3 px-4">
                      <select
                        value={alert.status}
                        onChange={(e) => handleStatusChange(alert.id, e.target.value)}
                        className="bg-soc-sidebar border border-soc-cardBorder text-[11px] text-white rounded-md px-2 py-1 focus:outline-none"
                      >
                        <option value="new">New</option>
                        <option value="acknowledged">Acknowledged</option>
                        <option value="investigating">Investigating</option>
                        <option value="escalated">Escalated</option>
                        <option value="dismissed">Dismissed</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="px-2.5 py-1 rounded-lg bg-soc-card border border-soc-cardBorder text-soc-textMuted hover:text-white transition-all text-xs"
                      >
                        Details
                      </button>
                      <Link
                        href={`/copilot?alert_id=${alert.id}&query=${encodeURIComponent(`Analyze alert: ${alert.title}`)}`}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 hover:bg-cyan-900/60 transition-all text-xs"
                      >
                        <Bot className="w-3.5 h-3.5" />
                        <span>AI Triage</span>
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Details Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder max-w-2xl w-full space-y-5 animate-scale-up">
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <SeverityBadge severity={selectedAlert.severity} />
                  <span className="text-xs font-mono text-soc-textMuted">{selectedAlert.id}</span>
                </div>
                <h3 className="text-lg font-bold text-white">{selectedAlert.title}</h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 rounded-lg hover:bg-soc-hover text-soc-textMuted hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-soc-textMuted font-medium">Description:</span>
                <p className="mt-1 text-white bg-soc-sidebar p-3 rounded-xl border border-soc-cardBorder">
                  {selectedAlert.description}
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 rounded-xl bg-soc-sidebar border border-soc-cardBorder">
                  <span className="text-soc-textMuted">Detection Rule:</span>
                  <div className="font-mono text-cyan-400 mt-0.5">{selectedAlert.rule_name || 'N/A'}</div>
                  {selectedAlert.detection_rule_version && (
                    <div className="text-[10px] text-soc-textMuted mt-1">
                      Rule version {selectedAlert.detection_rule_version}
                    </div>
                  )}
                </div>
                <div className="p-3 rounded-xl bg-soc-sidebar border border-soc-cardBorder">
                  <span className="text-soc-textMuted">Target Asset:</span>
                  <div className="font-mono text-amber-400 mt-0.5">{selectedAlert.asset_id || 'N/A'}</div>
                </div>
              </div>

              {(selectedAlert.risk_score != null ||
                selectedAlert.confidence != null ||
                selectedAlert.base_severity != null) && (
                <section className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/40 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="font-semibold text-cyan-200">Risk assessment</h4>
                    <span className="text-[10px] uppercase tracking-wide text-amber-300 border border-amber-800/50 rounded-full px-2 py-1">
                      Heuristic · not a probability
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <div className="text-soc-textMuted">Risk score</div>
                      <div className="text-white font-semibold">
                        {selectedAlert.risk_score != null
                          ? selectedAlert.risk_score + '/100'
                          : 'Not scored'}
                      </div>
                    </div>
                    <div>
                      <div className="text-soc-textMuted">Rule base severity</div>
                      <div className="text-white font-semibold capitalize">
                        {selectedAlert.base_severity || 'Unavailable'}
                      </div>
                    </div>
                    <div>
                      <div className="text-soc-textMuted">Evidence estimate</div>
                      <div className="text-white font-semibold">
                        {selectedAlert.confidence != null
                          ? Math.round(selectedAlert.confidence * 100) + '%'
                          : 'Unavailable'}
                      </div>
                      <div className="text-[10px] text-soc-textMuted">Policy-derived; not a probability</div>
                    </div>
                  </div>
                  {selectedAlert.risk_factors && Object.keys(selectedAlert.risk_factors).length > 0 && (
                    <div className="border-t border-cyan-900/40 pt-3">
                      <div className="text-soc-textMuted mb-2">Scoring inputs</div>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(selectedAlert.risk_factors)
                          .filter(([key]) => key !== 'score_label')
                          .map(([key, value]) => (
                            <span
                              key={key}
                              className="rounded-lg border border-soc-cardBorder bg-soc-sidebar px-2.5 py-1.5 text-[10px]"
                            >
                              <span className="text-soc-textMuted">
                                {key.replaceAll('_', ' ')}:
                              </span>{' '}
                              <span className="text-white">
                                {typeof value === 'boolean'
                                  ? (value ? 'yes' : 'no')
                                  : String(value ?? 'unknown').replaceAll('_', ' ')}
                              </span>
                            </span>
                          ))}
                      </div>
                    </div>
                  )}
                </section>
              )}

              {selectedAlert.assigned_to && (
                <div className="text-soc-textMuted">Assigned to: <span className="text-white">{selectedAlert.assigned_to}</span></div>
              )}
              {selectedAlert.correlation_reason && (
                <div className="p-3.5 rounded-xl bg-purple-950/40 border border-purple-800/40 text-purple-200">
                  <span className="font-semibold text-purple-300">Multi-Source Correlation Rationale:</span>
                  <p className="mt-1">{selectedAlert.correlation_reason}</p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-soc-cardBorder">
              <span className="text-[11px] text-soc-textMuted font-mono">
                Created: {new Date(selectedAlert.created_at).toLocaleString()}
              </span>
              <div className="flex space-x-2">
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="px-4 py-2 rounded-xl bg-soc-card border border-soc-cardBorder text-xs text-soc-textMuted hover:text-white"
                >
                  Close
                </button>
                <Link
                  href={`/copilot?alert_id=${selectedAlert.id}&query=${encodeURIComponent(`Investigate alert ${selectedAlert.title} on host ${selectedAlert.asset_id}`)}`}
                  className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-xs font-medium"
                >
                  <Bot className="w-4 h-4" />
                  <span>Launch Copilot Investigation</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
