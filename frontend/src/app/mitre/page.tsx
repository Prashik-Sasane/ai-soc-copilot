'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Grid,
  ShieldAlert,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
  Loader2,
  AlertCircle,
  Activity,
  X,
  ExternalLink,
  FileSearch,
  Zap,
  ListChecks,
  BookOpen,
  Eye,
  Lightbulb
} from 'lucide-react';
import {
  getMitreMatrix,
  triggerSyntheticScenario,
  triggerCorrelation,
  getIngestStatus
} from '@/lib/api';

type TechniqueT = {
  technique_id: string;
  name: string;
  description: string;
  platforms: string[];
  detected: boolean;
  severity?: string;
  confidence?: number;
  rationale?: string;
  related_incident_ids?: string[];
  related_alert_ids?: string[];
  detection_method?: string;
};

type TacticT = {
  id: string;
  name: string;
  count: number;
  techniques: TechniqueT[];
};

type MatrixResponse = {
  tactics: TacticT[];
  summary?: {
    total_techniques: number;
    detected_techniques: number;
    incidents_scanned: number;
    alerts_scanned: number;
  };
};

const severityStyles: Record<string, string> = {
  critical: 'bg-rose-950/40 border-rose-800/40 text-rose-200',
  high: 'bg-amber-950/40 border-amber-800/40 text-amber-200',
  medium: 'bg-cyan-950/40 border-cyan-800/40 text-cyan-200',
  low: 'bg-emerald-950/40 border-emerald-800/40 text-emerald-200',
};

const severityBadge: Record<string, string> = {
  critical: 'text-rose-300 bg-rose-950/70 border-rose-800/60',
  high: 'text-amber-300 bg-amber-950/70 border-amber-800/60',
  medium: 'text-cyan-300 bg-cyan-950/70 border-cyan-800/60',
  low: 'text-emerald-300 bg-emerald-950/70 border-emerald-800/60',
};

type InvestigationStep = string;

const investigationPlaybooks: Record<string, InvestigationStep[]> = {
  default: [
    'Review the raw command lines or process arguments associated with this technique.',
    'Check the parent process chain and identify the executing user.',
    'Correlate with nearby network connections and DNS activity.',
    'Identify endpoint telemetry source (EDR, sysmon, proxy logs) that fired detection.',
    'Determine scope of impacted hosts and user accounts.',
  ],
  Execution: [
    'Capture and analyze PowerShell / cmd / WMI command lines for encoded payloads.',
    'Check script block logs and transcription files for suspicious modules.',
    'Verify process parent-child relationships and execution lineage.',
    'Correlate with file creation events to find dropped artifacts.',
  ],
  'Initial Access': [
    'Identify the delivery vector (phishing email, USB, web exploit, RDP).',
    'Extract email headers, URL links, and attachment hashes from the original message.',
    'Check if the sender domain or IP is listed in threat intelligence feeds.',
    'Review authentication logs for any concurrent compromise attempts.',
  ],
  Persistence: [
    'Enumerate registry run keys, scheduled tasks, and startup folders.',
    'Check WMI event consumers and services for new unrecognized entries.',
    'Review Office add-ins, browser extensions, and shortcut modifications.',
    'Inspect new user accounts and group membership changes.',
  ],
  'Privilege Escalation': [
    'Review local admin and service account logon events on the target host.',
    'Check for token manipulation, UAC bypass, or vulnerable service exploitation.',
    'Inspect elevated process spawning and integrity level changes.',
  ],
  'Defense Evasion': [
    'Check for AMSI bypass attempts, PowerShell -NoProfile, or ETW tracing disabled.',
    'Review binary renamed LOLBINs (certutil, mshta, bitsadmin, regsvr32).',
    'Correlate with tamper events in EDR logs and disabled services.',
  ],
  'Credential Access': [
    'Capture memory dumps and LSASS process memory for forensic analysis.',
    'Audit Active Directory replication (DCSync) and Kerberos ticket usage.',
    'Check SAM hive access, Rubeus/Mimikatz indicators, and password spraying logs.',
  ],
  Discovery: [
    'Review net, dsquery, adfind, bloodhound-like enumeration commands.',
    'Check for LDAP/SMB sweeps and reconnaissance attempts across subnets.',
  ],
  'Lateral Movement': [
    'Review SMB/WinRM/RDP/WMI authentications to other hosts post-compromise.',
    'Map destination hosts to identify the scope of lateral movement.',
    'Inspect psexec, wmic, winrs, and named pipe activity.',
  ],
  Collection: [
    'Identify data staging directories (TEMP, ProgramData, C:\\Users\\Public).',
    'Check archiving commands (7z, rar, zip) and large file exfil staging.',
  ],
  'Command and Control': [
    'Extract destination IP, domain, and URL IOCs from proxy and DNS logs.',
    'Capture beaconing patterns, user-agent strings, and TLS certificate anomalies.',
    'Block the destination at the firewall and sinkhole DNS where possible.',
  ],
  Exfiltration: [
    'Check upload size spikes to cloud storage, pastebin, FTP, or web DAV.',
    'Review DNS tunneling, ICMP, or HTTP POST exfil patterns.',
  ],
  Impact: [
    'Review volume shadow copy deletion, bitlocker, or ransomware-like encryption behavior.',
    'Identify wbadmin / vssadmin deletion and destructive scheduled tasks.',
    'Assess business impact and initiate IR playbook for recovery.',
  ],
};

export default function MitrePage() {
  const [data, setData] = useState<MatrixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [selectedTechnique, setSelectedTechnique] = useState<{
    tactic: string;
    tech: TechniqueT;
  } | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getMitreMatrix();
      setData(res as MatrixResponse);
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to load MITRE matrix');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    getIngestStatus()
      .then((s) => setDemoEnabled(s?.demo_seeding_enabled === true))
      .catch(() => setDemoEnabled(false));
  }, []);

  const handleGenerateData = async () => {
    setGenerating(true);
    setError(null);
    try {
      await triggerSyntheticScenario();
      try {
        await triggerCorrelation();
      } catch {}
      await loadData();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to generate data');
    } finally {
      setGenerating(false);
    }
  };

  const tactics = data?.tactics || [];
  const totalDetected = tactics.reduce((s, t) => s + t.count, 0);
  const totalTechs = tactics.reduce((s, t) => s + t.techniques.length, 0);

  const getInvestigationSteps = (tacticName: string): InvestigationStep[] => {
    return investigationPlaybooks[tacticName] || investigationPlaybooks.default;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Grid className="w-6 h-6 text-cyan-400" />
            <span>MITRE ATT&amp;CK Matrix Explorer</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Click any technique tile to open investigation details, related incidents, and analyst playbooks.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-cyan-500/50 transition-all text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {demoEnabled && (
            <button
              onClick={handleGenerateData}
              disabled={generating}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium transition-all shadow-cyan-glow disabled:opacity-50"
            >
              {generating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
              {generating ? 'Generating...' : 'Generate Attack Data'}
            </button>
          )}
        </div>
      </div>

      {/* Summary Stats */}
      {data?.summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-soc-textMuted uppercase tracking-wider font-mono">Coverage</p>
            <p className="text-xl font-bold text-white mt-1">
              {data.summary.total_techniques} <span className="text-xs text-soc-textMuted font-normal">Techniques</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-rose-400 uppercase tracking-wider font-mono">Active Detections</p>
            <p className="text-xl font-bold text-rose-400 mt-1">
              {data.summary.detected_techniques} <span className="text-xs text-soc-textMuted font-normal">Techniques</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-amber-400 uppercase tracking-wider font-mono">Incidents Scanned</p>
            <p className="text-xl font-bold text-amber-400 mt-1">
              {data.summary.incidents_scanned} <span className="text-xs text-soc-textMuted font-normal">Total</span>
            </p>
          </div>
          <div className="glass-panel p-4 rounded-2xl border border-soc-cardBorder">
            <p className="text-[11px] text-cyan-400 uppercase tracking-wider font-mono">Alerts Scanned</p>
            <p className="text-xl font-bold text-cyan-400 mt-1">
              {data.summary.alerts_scanned} <span className="text-xs text-soc-textMuted font-normal">Total</span>
            </p>
          </div>
        </div>
      )}

      {error && (
        <div className="glass-panel p-4 rounded-2xl border border-rose-800/50 bg-rose-950/20 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-rose-300 font-semibold">Error</p>
            <p className="text-xs text-rose-200/70 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {loading ? (
        <div className="glass-panel p-16 rounded-2xl border border-soc-cardBorder text-center">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-sm text-soc-textMuted font-mono">Analyzing alerts and incidents for MITRE ATT&amp;CK mapping...</p>
        </div>
      ) : (
        <>
          {totalDetected === 0 && totalTechs > 0 && (
            <div className="glass-panel p-5 rounded-2xl border border-cyan-800/40 bg-cyan-950/10 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm text-cyan-300 font-semibold">No detections yet</p>
                <p className="text-xs text-cyan-200/70 mt-0.5">
                  The system found no evidence matching ATT&amp;CK techniques in your current tenant workspace.
                  Click <span className="font-mono text-cyan-300">&quot;Generate Attack Data&quot;</span> to seed a synthetic
                  multi-stage attack scenario and see detections populate the matrix.
                </p>
              </div>
              <button
                onClick={handleGenerateData}
                disabled={generating}
                className="shrink-0 px-3 py-1.5 rounded-lg bg-cyan-950/60 text-cyan-300 border border-cyan-800/40 hover:bg-cyan-900/60 text-xs font-medium transition-all disabled:opacity-50"
              >
                Generate Scenario
              </button>
            </div>
          )}

          {/* Grid columns of tactics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {tactics
              .filter((t) => t.techniques.length > 0)
              .map((tactic) => (
                <div
                  key={tactic.id}
                  className="glass-panel p-4 rounded-2xl border border-soc-cardBorder space-y-3 flex flex-col"
                >
                  <div className="flex items-center justify-between border-b border-soc-cardBorder pb-2">
                    <span className="font-bold text-sm text-white leading-snug pr-2">{tactic.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded border text-xs font-mono shrink-0 ${
                        tactic.count > 0
                          ? 'bg-rose-950/60 border-rose-800/40 text-rose-300'
                          : 'bg-soc-sidebar border-soc-cardBorder text-soc-textMuted'
                      }`}
                    >
                      {tactic.count} Detected
                    </span>
                  </div>

                  <div className="space-y-2 flex-1">
                    {tactic.techniques.length === 0 ? (
                      <div className="text-xs text-soc-textMuted italic py-4 text-center">
                        No technique references available
                      </div>
                    ) : (
                      tactic.techniques.map((tech) => (
                        <button
                          key={tech.technique_id}
                          onClick={() => setSelectedTechnique({ tactic: tactic.name, tech })}
                          className={`w-full text-left p-3 rounded-xl border text-xs space-y-1.5 cursor-pointer transition-all ${
                            tech.detected
                              ? `${severityStyles[tech.severity || 'medium']} hover:shadow-lg hover:ring-1 hover:ring-offset-0 ring-white/10`
                              : 'bg-soc-sidebar/60 border-soc-cardBorder/60 text-soc-textMuted/70 opacity-70 hover:opacity-100 hover:bg-soc-sidebar'
                          }`}
                        >
                          <div className="flex items-center justify-between font-mono text-[11px]">
                            <span className={`font-bold ${tech.detected ? '' : 'text-soc-textMuted/60'}`}>
                              {tech.technique_id}
                            </span>
                            <div className="flex items-center gap-2">
                              {tech.confidence !== undefined && tech.confidence !== null && (
                                <span className="text-[10px] opacity-80">
                                  {Math.round(tech.confidence * 100)}%
                                </span>
                              )}
                              {tech.detected ? (
                                <ShieldAlert className="w-3.5 h-3.5 shrink-0" />                              ) : (
                                <span className="text-[10px] font-mono opacity-50">undetected</span>
                              )}
                            </div>
                          </div>
                          <div className="font-semibold leading-snug flex items-center gap-1.5 pr-2">
                            <span>{tech.name}</span>
                            <Eye className="w-3 h-3 ml-auto shrink-0 opacity-60" />
                          </div>
                          {tech.rationale && tech.detected && (
                            <p className="text-[10px] opacity-80 font-mono italic bg-soc-card/60 p-2 rounded border border-soc-cardBorder/60 line-clamp-2">
                              {tech.rationale}
                            </p>
                          )}
                        </button>
                      ))
                    )}
                  </div>
                </div>
              ))}
          </div>
        </>
      )}

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 animate-fade-in">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setSelectedTechnique(null)}
          />
          <div className="relative w-full max-w-3xl max-h-[88vh] overflow-y-auto overflow-x-hidden rounded-2xl border border-soc-cardBorder bg-soc-bg/95 backdrop-blur-xl shadow-2xl">
            {/* Modal Header */}
            <div className="sticky top-0 z-10 flex items-start justify-between gap-3 p-5 sm:p-6 border-b border-soc-cardBorder bg-soc-bg/95 backdrop-blur-xl">
              <div className="flex-1 min-w-0 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/50 tracking-wider">
                    {selectedTechnique.tactic}
                  </span>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-cyan-300">
                    MITRE ATT&amp;CK: {selectedTechnique.tech.technique_id}
                  </span>
                  {selectedTechnique.tech.detected && selectedTechnique.tech.severity && (
                    <span
                      className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded border tracking-wider ${
                        severityBadge[selectedTechnique.tech.severity]
                      }`}
                    >
                      {selectedTechnique.tech.severity}
                    </span>
                  )}
                </div>
                <h2 className="text-xl font-bold text-white leading-tight break-words">
                  {selectedTechnique.tech.name}
                </h2>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="shrink-0 w-8 h-8 rounded-lg bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-rose-500/50 transition-all inline-flex items-center justify-center"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 sm:p-6 space-y-6">
              {/* Technique Description */}
              <section className="space-y-2">
                <p className="text-sm text-soc-textMuted leading-relaxed">
                  {selectedTechnique.tech.description}
                </p>
                {selectedTechnique.tech.platforms && selectedTechnique.tech.platforms.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {selectedTechnique.tech.platforms.map((p) => (
                      <span
                        key={p}
                        className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                )}
              </section>

              {/* Detection / Why detected */}
              {selectedTechnique.tech.detected ? (
                <section className="space-y-3 p-4 rounded-2xl border border-rose-900/40 bg-rose-950/15">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <h3 className="font-semibold text-rose-300 text-sm">Why was this detected?</h3>
                  </div>
                  <p className="text-xs text-rose-100/85 leading-relaxed pl-6">
                    {selectedTechnique.tech.rationale ||
                      'The application associated this technique with one or more security incidents. Review the evidence references to understand the match.'}
                  </p>
                  <div className="pl-6 grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    <div className="p-3 rounded-xl bg-soc-sidebar/70 border border-soc-cardBorder/70 space-y-1.5">
                      <h4 className="text-[10px] font-mono uppercase tracking-wider text-soc-textMuted">
                        Detection Method
                      </h4>
                      <p className="text-xs font-semibold text-white">
                        {selectedTechnique.tech.detection_method || 'Keyword + incident correlation'}
                      </p>
                    </div>
                    <div className="p-3 rounded-xl bg-soc-sidebar/70 border border-soc-cardBorder/70 space-y-1.5">
                      <h4 className="text-[10px] font-mono uppercase tracking-wider text-soc-textMuted">
                        Analyst Confidence
                      </h4>
                      <p className="text-xs font-semibold text-white">
                        {selectedTechnique.tech.confidence !== undefined
                          ? `${Math.round((selectedTechnique.tech.confidence || 0) * 100)}% match score`
                          : 'N/A'}
                      </p>
                    </div>
                  </div>
                </section>
              ) : (
                <section className="space-y-2 p-4 rounded-2xl border border-soc-cardBorder bg-soc-sidebar/50">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <h3 className="font-semibold text-white text-sm">No Active Detection</h3>
                  </div>
                  <p className="text-xs text-soc-textMuted leading-relaxed pl-6">
                    This technique is listed as ATT&amp;CK reference data but the system did not find matching
                    telemetry. Use this panel as a reference when conducting proactive threat hunting.
                  </p>
                </section>
              )}

              {/* Related Incident */}
              <section className="space-y-3">
                <div className="flex items-center gap-2">
                  <FileSearch className="w-4 h-4 text-cyan-400" />
                  <h3 className="font-semibold text-white text-sm">Related Incidents</h3>
                </div>
                {selectedTechnique.tech.related_incident_ids &&
                selectedTechnique.tech.related_incident_ids.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {selectedTechnique.tech.related_incident_ids.map((iid) => (
                      <Link
                        key={iid}
                        href={`/incidents?incident_id=${encodeURIComponent(iid)}`}
                        className="group flex items-center justify-between p-3 rounded-xl border border-soc-cardBorder bg-soc-sidebar/70 hover:border-cyan-500/50 hover:bg-soc-sidebar transition-all"
                      >
                        <div className="min-w-0 pr-2">
                          <p className="text-[10px] font-mono text-soc-textMuted uppercase tracking-wider">
                            Incident ID
                          </p>
                          <p className="text-xs font-mono text-cyan-300 truncate">{iid}</p>
                        </div>
                        <span className="shrink-0 flex items-center gap-1 text-xs text-soc-textMuted group-hover:text-cyan-300 transition-colors">
                          View incident
                          <ArrowRight className="w-3 h-3" />
                        </span>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-soc-textMuted/70 italic pl-6">
                    No directly-tagged incidents. Generate the demo attack scenario to populate this section.
                  </p>
                )}
              </section>

              {/* Evidence */}
              <section className="space-y-3">
                <div className="flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-purple-400" />
                  <h3 className="font-semibold text-white text-sm">Evidence & Alerts</h3>
                </div>
                {selectedTechnique.tech.related_alert_ids &&
                selectedTechnique.tech.related_alert_ids.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {selectedTechnique.tech.related_alert_ids.map((aid) => (
                      <Link
                        key={aid}
                        href={`/copilot?alert_id=${encodeURIComponent(aid)}&query=${encodeURIComponent(
                          `Analyze alert ${aid} and provide evidence context`
                        )}`}
                        className="group flex items-center justify-between p-3 rounded-xl border border-soc-cardBorder bg-soc-sidebar/70 hover:border-purple-500/50 hover:bg-soc-sidebar transition-all"
                      >
                        <div className="min-w-0 pr-2">
                          <p className="text-[10px] font-mono text-soc-textMuted uppercase tracking-wider">
                            Alert ID
                          </p>
                          <p className="text-xs font-mono text-purple-300 truncate">{aid}</p>
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-soc-textMuted/70 italic pl-6">
                    No alert IOCs directly referenced yet.
                  </p>
                )}
                <div className="pl-6 pt-1">
                  <Link
                    href={`/copilot?query=${encodeURIComponent(
                      `Show me all evidence, events, and alerts matching ${selectedTechnique.tech.technique_id} ${selectedTechnique.tech.name} and explain detection`
                    )}`}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-purple-950/60 border border-purple-800/50 text-purple-200 hover:text-white hover:bg-purple-900/70 text-xs font-medium transition-all"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    View all events in AI Copilot →
                  </Link>
                </div>
              </section>

              {/* Recommended Investigation Playbook */}
              <section className="space-y-3">
                <div className="flex items-center gap-2">
                  <ListChecks className="w-4 h-4 text-amber-400" />
                  <h3 className="font-semibold text-white text-sm">Recommended Investigation</h3>
                </div>
                <ol className="pl-6 space-y-2.5">
                  {getInvestigationSteps(selectedTechnique.tactic).map((step, idx) => (
                    <li key={idx} className="flex gap-3">
                      <span className="shrink-0 w-5 h-5 rounded-full bg-amber-950/70 border border-amber-800/60 text-amber-300 text-[10px] font-mono font-bold inline-flex items-center justify-center mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="text-xs text-white/90 leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ol>
                <div className="pl-6 pt-1 flex flex-wrap gap-2">
                  <Link
                    href={`/copilot?query=${encodeURIComponent(
                      `Investigate ${selectedTechnique.tech.technique_id} ${selectedTechnique.tech.name} following the ${selectedTechnique.tactic} incident response playbook and output containment steps`
                    )}`}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-xs font-medium transition-all shadow-purple-glow"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    Run investigation in AI Copilot →
                  </Link>
                  <Link
                    href="/knowledge"
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-cyan-500/50 text-xs font-medium transition-all"
                  >
                    <Lightbulb className="w-3.5 h-3.5" />
                    Browse Knowledge Playbooks →
                  </Link>
                </div>
              </section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
