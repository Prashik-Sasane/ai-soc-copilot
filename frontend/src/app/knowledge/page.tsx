'use client';

import React from 'react';
import { BookOpen, ShieldCheck, FileText, CheckCircle2, User } from 'lucide-react';

export default function KnowledgePage() {
  const playbooks = [
    {
      title: 'LSASS Memory Dumping Containment & Forensic Recovery',
      category: 'Incident Response Playbook',
      chunks: 8,
      status: 'Indexed in pgvector',
      updated: '2026-09-28',
    },
    {
      title: 'Obfuscated Command-Line Detection & PowerShell Analysis',
      category: 'Detection Advisory',
      chunks: 12,
      status: 'Indexed in pgvector',
      updated: '2026-09-27',
    },
    {
      title: 'Enterprise Perimeter Firewall C2 Egress Blocking Standard',
      category: 'Security Standard',
      chunks: 5,
      status: 'Indexed in pgvector',
      updated: '2026-09-26',
    },
  ];

  const auditLogs = [
    {
      id: 'aud_101',
      timestamp: '2026-09-28 05:08:15',
      user: 'Analyst Security Admin',
      action: 'EXECUTE_CONTAINMENT',
      resource: 'WORKSTATION-089 (Host Isolation)',
      ip: '10.0.1.5',
    },
    {
      id: 'aud_102',
      timestamp: '2026-09-28 05:07:44',
      user: 'AI SOC Copilot Agent',
      action: 'RUN_INVESTIGATION_WORKFLOW',
      resource: 'inc_sim_001',
      ip: '127.0.0.1',
    },
    {
      id: 'aud_103',
      timestamp: '2026-09-28 05:04:10',
      user: 'Analyst Security Admin',
      action: 'STATUS_UPDATE',
      resource: 'alt_sim_002 -> investigating',
      ip: '10.0.1.5',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
          <BookOpen className="w-6 h-6 text-purple-400" />
          <span>RAG Knowledge Base & System Audit Trail</span>
        </h1>
        <p className="text-sm text-soc-textMuted mt-1">
          Vectorized playbooks for RAG retrieval and complete immutable analyst audit history.
        </p>
      </div>

      {/* RAG Playbooks */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <span>Approved RAG Knowledge Base Playbooks</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {playbooks.map((pb, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-2">
              <span className="text-[11px] font-mono text-purple-400 uppercase">{pb.category}</span>
              <h3 className="font-semibold text-sm text-white">{pb.title}</h3>
              <div className="flex items-center justify-between text-xs text-soc-textMuted pt-2 border-t border-soc-cardBorder">
                <span className="text-emerald-400 font-mono flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  {pb.status}
                </span>
                <span>{pb.chunks} chunks</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span>Analyst Action & AI Copilot Audit History</span>
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-soc-sidebar/80 border-b border-soc-cardBorder font-mono uppercase text-soc-textMuted text-[10px]">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">User / Agent</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target Resource</th>
                <th className="py-2.5 px-3">IP Address</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-cardBorder">
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-soc-hover/50">
                  <td className="py-2.5 px-3 font-mono text-soc-textMuted">{log.timestamp}</td>
                  <td className="py-2.5 px-3 font-medium text-white flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{log.user}</span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-amber-400">{log.action}</td>
                  <td className="py-2.5 px-3 text-soc-textMain">{log.resource}</td>
                  <td className="py-2.5 px-3 font-mono text-soc-textMuted">{log.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
