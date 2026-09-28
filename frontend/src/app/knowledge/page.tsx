'use client';

import React, { useEffect, useState } from 'react';
import {
  BookOpen,
  ShieldCheck,
  FileText,
  CheckCircle2,
  User,
  RefreshCw,
  Database,
  AlertCircle,
  Loader2
} from 'lucide-react';
import {
  getKnowledgeDocuments,
  getAuditLogs,
  seedKnowledgePlaybooks,
  KnowledgeDocument,
  AuditLogEntry
} from '@/lib/api';

const categoryLabels: Record<string, string> = {
  playbook: 'Incident Response Playbook',
  advisory: 'Detection Advisory',
  mitre_ref: 'MITRE Reference',
  standard: 'Security Standard',
};

export default function KnowledgePage() {
  const [documents, setDocuments] = useState<KnowledgeDocument[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [docs, logs] = await Promise.all([
        getKnowledgeDocuments(),
        getAuditLogs(),
      ]);
      setDocuments(docs || []);
      setAuditLogs(logs || []);
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to load data');
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
      await seedKnowledgePlaybooks();
      await loadData();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to seed playbooks');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <BookOpen className="w-6 h-6 text-purple-400" />
            <span>RAG Knowledge Base & System Audit Trail</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Vectorized playbooks for RAG retrieval and complete immutable analyst audit history.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-purple-500/50 transition-all text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleSeed}
            disabled={seeding || loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-medium transition-all shadow-purple-glow disabled:opacity-50"
          >
            {seeding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
            {seeding ? 'Seeding...' : 'Seed Default Playbooks'}
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

      {/* RAG Playbooks */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Approved RAG Knowledge Base Playbooks</span>
          </h2>
          <span className="px-2.5 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-xs font-mono text-cyan-400">
            {documents.length} Documents
          </span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-soc-textMuted text-xs font-mono">
            <Loader2 className="w-4 h-4 animate-spin mr-2" />
            Loading knowledge base...
          </div>
        ) : documents.length === 0 ? (
          <div className="text-center py-16 space-y-3">
            <div className="w-12 h-12 rounded-xl bg-soc-sidebar border border-soc-cardBorder flex items-center justify-center mx-auto">
              <BookOpen className="w-6 h-6 text-soc-textMuted" />
            </div>
            <p className="text-sm text-soc-textMuted">
              No playbooks indexed yet. Seed the default IR playbooks to enable RAG-powered Copilot.
            </p>
            <button
              onClick={handleSeed}
              disabled={seeding}
              className="px-4 py-2 rounded-xl bg-purple-950/60 text-purple-300 border border-purple-800/40 hover:bg-purple-900/60 text-xs font-medium transition-all disabled:opacity-50"
            >
              {seeding ? 'Seeding Playbooks...' : 'Seed Default Playbooks'}
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {documents.map((doc) => (
              <div
                key={doc.id}
                className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-2 hover:border-purple-500/40 transition-all group"
              >
                <span className="text-[11px] font-mono text-purple-400 uppercase">
                  {categoryLabels[doc.category] || doc.category}
                </span>
                <h3 className="font-semibold text-sm text-white leading-snug">{doc.title}</h3>
                <p className="text-[11px] text-soc-textMuted line-clamp-2 leading-relaxed">
                  {doc.content.replace(/\s+/g, ' ').slice(0, 160)}...
                </p>
                <div className="flex items-center justify-between text-xs text-soc-textMuted pt-2 border-t border-soc-cardBorder">
                  <span
                    className="text-emerald-400 font-mono flex items-center gap-1"
                    title={doc.status}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    {doc.status}
                  </span>
                  <span>{doc.chunk_count} chunks</span>
                </div>
                <div className="text-[10px] text-soc-textMuted/70 font-mono pt-1">
                  Updated: {new Date(doc.updated_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Audit Log Table */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>Analyst Action & AI Copilot Audit History</span>
          </h2>
          <span className="px-2.5 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-xs font-mono text-emerald-400">
            {auditLogs.length} Entries
          </span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12 text-soc-textMuted text-xs font-mono">
            <Loader2 className="w-4 h-4 animate-spin mr-2" />
            Loading audit trail...
          </div>
        ) : auditLogs.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-sm text-soc-textMuted italic">No audit logs yet. Activity will appear here as actions are performed.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-soc-sidebar/80 border-b border-soc-cardBorder font-mono uppercase text-soc-textMuted text-[10px]">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">User / Agent</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Target Resource</th>
                  <th className="py-2.5 px-3">Details</th>
                  <th className="py-2.5 px-3">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-cardBorder">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-soc-hover/50">
                    <td className="py-2.5 px-3 font-mono text-soc-textMuted whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-white flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="truncate max-w-[140px]">
                        {log.user_email || log.user_id || 'System'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-amber-400 whitespace-nowrap">
                      {log.action}
                    </td>
                    <td className="py-2.5 px-3 text-soc-textMain whitespace-nowrap">
                      {log.resource_type}
                      {log.resource_id && (
                        <span className="text-soc-textMuted font-mono ml-1 text-[10px]">
                          ({log.resource_id.slice(0, 18)}
                          {log.resource_id.length > 18 ? '...' : ''})
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-[11px] text-soc-textMuted max-w-[240px]">
                      {log.details_json ? (
                        typeof log.details_json === 'string' ? (
                          <span className="truncate block">{log.details_json}</span>
                        ) : (
                          <span className="truncate block">
                            {log.details_json?.message ||
                              log.details_json?.title ||
                              JSON.stringify(log.details_json).slice(0, 80)}
                          </span>
                        )
                      ) : (
                        <span className="italic text-soc-textMuted/60">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-soc-textMuted whitespace-nowrap">
                      {log.ip_address || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
