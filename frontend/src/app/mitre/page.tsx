'use client';

import React, { useEffect, useState } from 'react';
import { Grid, ShieldAlert, CheckCircle2, ArrowRight } from 'lucide-react';
import { getMitreMatrix } from '@/lib/api';

export default function MitrePage() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    getMitreMatrix().then(setData).catch(console.error);
  }, []);

  const tacticsList = [
    { id: 'TA0001', name: 'Initial Access', count: 1, techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', severity: 'medium' }] },
    { id: 'TA0002', name: 'Execution', count: 2, techniques: [{ id: 'T1059.001', name: 'PowerShell', severity: 'high' }] },
    { id: 'TA0003', name: 'Persistence', count: 0, techniques: [] },
    { id: 'TA0004', name: 'Privilege Escalation', count: 0, techniques: [] },
    { id: 'TA0005', name: 'Defense Evasion', count: 1, techniques: [{ id: 'T1027', name: 'Obfuscated Command', severity: 'medium' }] },
    { id: 'TA0006', name: 'Credential Access', count: 2, techniques: [{ id: 'T1003.001', name: 'LSASS Memory Dump', severity: 'critical' }] },
    { id: 'TA0011', name: 'Command & Control', count: 2, techniques: [{ id: 'T1071.001', name: 'Web Protocols (TLS)', severity: 'high' }] },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Grid className="w-6 h-6 text-cyan-400" />
          <span>MITRE ATT&CK Matrix Explorer</span>
        </h1>
        <p className="text-sm text-soc-textMuted mt-1">
          Observed adversary tactics & techniques mapped across enterprise telemetry.
        </p>
      </div>

      {/* Grid columns of tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {tacticsList.map((tactic) => (
          <div key={tactic.id} className="glass-panel p-4 rounded-2xl border border-soc-cardBorder space-y-3">
            <div className="flex items-center justify-between border-b border-soc-cardBorder pb-2">
              <span className="font-bold text-sm text-white">{tactic.name}</span>
              <span className="px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-xs font-mono text-cyan-400">
                {tactic.count} Mapped
              </span>
            </div>

            <div className="space-y-2">
              {tactic.techniques.length === 0 ? (
                <div className="text-xs text-soc-textMuted italic py-4 text-center">
                  No active detections in window
                </div>
              ) : (
                tactic.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    className={`p-3 rounded-xl border text-xs space-y-1 ${
                      tech.severity === 'critical'
                        ? 'bg-rose-950/40 border-rose-800/40 text-rose-200'
                        : tech.severity === 'high'
                        ? 'bg-amber-950/40 border-amber-800/40 text-amber-200'
                        : 'bg-cyan-950/40 border-cyan-800/40 text-cyan-200'
                    }`}
                  >
                    <div className="flex items-center justify-between font-mono text-[11px] font-bold">
                      <span>{tech.id}</span>
                      <span className="uppercase text-[10px]">{tech.severity}</span>
                    </div>
                    <div className="font-semibold">{tech.name}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
