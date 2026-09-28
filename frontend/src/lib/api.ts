// AI SOC Copilot API Client & Fallback Engine

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export interface AlertItem {
  id: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'acknowledged' | 'investigating' | 'dismissed' | 'resolved';
  source: string;
  rule_name?: string;
  asset_id?: string;
  event_ids: string[];
  correlated_group_id?: string;
  correlation_reason?: string;
  created_at: string;
  updated_at?: string;
}

export interface IncidentItem {
  id: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'investigating' | 'contained' | 'resolved' | 'closed';
  lead_analyst_id?: string;
  alert_ids: string[];
  indicator_ids: string[];
  mitre_techniques: string[];
  timeline_json: Array<{
    timestamp: string;
    event_type: string;
    title: string;
    description: string;
    severity: string;
    source: string;
  }>;
  recommendations_json: Array<{
    category: 'response' | 'investigative';
    title: string;
    description: string;
    priority: 'high' | 'medium' | 'low';
    requires_approval: boolean;
  }>;
  created_at: string;
  updated_at: string;
}

export interface IndicatorItem {
  id: string;
  indicator_value: string;
  indicator_type: 'ip' | 'domain' | 'file_hash' | 'url';
  reputation_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  threat_actor?: string;
  source_attribution?: string;
  raw_enrichment?: any;
  confidence: number;
  created_at: string;
}

export interface CopilotResponse {
  investigation_id: string;
  query: string;
  summary: string;
  findings: string[];
  mitre_mappings: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    confidence: number;
    evidence_snippet: string;
  }>;
  cited_evidence: Array<{
    citation_id: string;
    source_type: string;
    source_id: string;
    title: string;
    snippet: string;
    relevance_score: number;
  }>;
  recommendations: Array<{
    category: string;
    title: string;
    description: string;
    priority: string;
    requires_approval: boolean;
  }>;
  confidence: number;
  limitations: string[];
  timestamp: string;
}

// Default Fallback Data (Enables standalone high-fidelity UI demonstration)
const MOCK_ALERTS: AlertItem[] = [
  {
    id: 'alt_sim_001',
    title: 'Suspicious Obfuscated PowerShell Execution',
    description: 'Encoded PowerShell script spawned by Office binary WINWORD.EXE downloading external payload.',
    severity: 'high',
    status: 'new',
    source: 'edr',
    rule_name: 'EDR_RULE_POWERSHELL_ENC',
    asset_id: 'WORKSTATION-089',
    event_ids: ['evt_002'],
    created_at: new Date(Date.now() - 30 * 60000).toISOString(),
  },
  {
    id: 'alt_sim_002',
    title: 'Potential LSASS Credential Dumping via Comsvcs',
    description: 'Process comsvcs.dll attempted to generate minidump of lsass.exe process memory.',
    severity: 'critical',
    status: 'investigating',
    source: 'edr',
    rule_name: 'EDR_RULE_LSASS_DUMP',
    asset_id: 'WORKSTATION-089',
    event_ids: ['evt_003'],
    created_at: new Date(Date.now() - 25 * 60000).toISOString(),
  },
  {
    id: 'alt_sim_003',
    title: 'Outbound C2 Beaconing to Known Malicious IP',
    description: 'WORKSTATION-089 established outbound TLS connection to high-risk IP 198.51.100.44.',
    severity: 'high',
    status: 'acknowledged',
    source: 'firewall',
    rule_name: 'FW_RULE_C2_OUTBOUND',
    asset_id: 'WORKSTATION-089',
    event_ids: ['evt_004', 'evt_005'],
    created_at: new Date(Date.now() - 10 * 60000).toISOString(),
  },
  {
    id: 'alt_sim_004',
    title: 'Suspicious Password Spraying Attempt',
    description: 'Multiple failed authentication attempts across 14 accounts originating from IP 198.51.100.99.',
    severity: 'medium',
    status: 'new',
    source: 'identity',
    rule_name: 'IAM_RULE_PASS_SPRAY',
    asset_id: 'AUTH-DC-01',
    event_ids: ['evt_006'],
    created_at: new Date(Date.now() - 5 * 60000).toISOString(),
  },
];

const MOCK_INCIDENT: IncidentItem = {
  id: 'inc_sim_001',
  title: 'Multi-Stage Credential Theft & Outbound C2 on WORKSTATION-089',
  description: 'Attack chain detected: Spearphishing delivery followed by encoded PowerShell execution, LSASS memory dumping, and TLS beaconing.',
  severity: 'critical',
  status: 'investigating',
  lead_analyst_id: 'Analyst Security Admin',
  alert_ids: ['alt_sim_001', 'alt_sim_002', 'alt_sim_003'],
  indicator_ids: ['ind_001', 'ind_002'],
  mitre_techniques: ['T1059.001', 'T1003.001', 'T1071.001', 'T1566.002'],
  timeline_json: [
    {
      timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
      event_type: 'phishing_delivery',
      title: 'Phishing Email Delivered',
      description: 'Inbound email with malicious link http://phish-payroll-update.net/login.php received by victim.user@enterprise.com',
      severity: 'medium',
      source: 'email_gateway',
    },
    {
      timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
      event_type: 'process_creation',
      title: 'Encoded PowerShell Spawned',
      description: 'WINWORD.EXE launched obfuscated powershell.exe script downloading payload from 198.51.100.44.',
      severity: 'high',
      source: 'edr',
    },
    {
      timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
      event_type: 'credential_dump',
      title: 'LSASS Memory Dump Executed',
      description: 'rundll32.exe comsvcs.dll dumped LSASS process memory to C:\\Windows\\Temp\\lsass.dmp',
      severity: 'critical',
      source: 'edr',
    },
    {
      timestamp: new Date(Date.now() - 10 * 60000).toISOString(),
      event_type: 'network_conn',
      title: 'Outbound TLS C2 Channel Established',
      description: 'Active socket session established to 198.51.100.44:443',
      severity: 'high',
      source: 'firewall',
    },
  ],
  recommendations_json: [
    {
      category: 'response',
      title: 'Isolate WORKSTATION-089 from Enterprise Network',
      description: 'Execute EDR network isolation action on host WORKSTATION-089 to sever active C2 channel.',
      priority: 'high',
      requires_approval: true,
    },
    {
      category: 'response',
      title: 'Revoke User Session & Force Password Reset',
      description: 'Reset victim.user@enterprise.com credentials and invalidate Azure AD active refresh tokens.',
      priority: 'high',
      requires_approval: true,
    },
    {
      category: 'investigative',
      title: 'Block External IP 198.51.100.44 at Edge Firewall',
      description: 'Add 198.51.100.44 and c2-command-node.ru to perimeter blocklist.',
      priority: 'medium',
      requires_approval: false,
    },
  ],
  created_at: new Date(Date.now() - 30 * 60000).toISOString(),
  updated_at: new Date().toISOString(),
};

// Generic Fetch Wrapper
async function fetchAPI<T>(endpoint: string, options?: RequestInit, fallbackData?: T): Promise<T> {
  try {
    const res = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers: {
        'Content-Type': 'application/json',
      },
      ...options,
    });
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.warn(`[AI SOC API Warning] Backend endpoint ${endpoint} unreachable. Using simulated live data response.`);
    if (fallbackData !== undefined) {
      return fallbackData;
    }
    throw err;
  }
}

// API Methods
export async function getDashboardStats() {
  return fetchAPI('/dashboard/stats', { method: 'GET' }, {
    total_events: 14250,
    total_alerts: 24,
    open_incidents: 3,
    critical_incidents: 1,
    mean_time_to_respond_mins: 14.2,
    threat_level: 'ELEVATED (DEFCON 3)',
    alerts_by_severity: { critical: 2, high: 7, medium: 10, low: 5 },
    alerts_by_source: { edr: 10, firewall: 6, identity: 4, dns: 4 },
  });
}

export async function triggerSyntheticScenario() {
  return fetchAPI('/events/simulate-scenario', { method: 'POST' }, {
    status: 'success',
    message: 'Synthetic multi-stage attack scenario generated successfully.',
    scenario: 'Phishing -> Encoded PowerShell -> LSASS Dump -> C2 Beaconing',
  });
}

export async function getAlerts() {
  return fetchAPI<{ items: AlertItem[]; total: number }>('/alerts', { method: 'GET' }, {
    items: MOCK_ALERTS,
    total: MOCK_ALERTS.length,
  });
}

export async function updateAlertStatus(alertId: string, status: string) {
  return fetchAPI<AlertItem>(`/alerts/${alertId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  }, {
    ...MOCK_ALERTS[0],
    id: alertId,
    status: status as any,
  });
}

export async function getIncidents() {
  return fetchAPI<{ items: IncidentItem[]; total: number }>('/incidents', { method: 'GET' }, {
    items: [MOCK_INCIDENT],
    total: 1,
  });
}

export async function getIncidentById(incidentId: string) {
  return fetchAPI<IncidentItem>(`/incidents/${incidentId}`, { method: 'GET' }, MOCK_INCIDENT);
}

export async function queryCopilot(query: string, incidentId?: string, alertId?: string): Promise<CopilotResponse> {
  return fetchAPI<CopilotResponse>('/copilot/query', {
    method: 'POST',
    body: JSON.stringify({ query, incident_id: incidentId, alert_id: alertId }),
  }, {
    investigation_id: `inv_${Math.random().toString(36).substring(2, 9)}`,
    query,
    summary: `Analysis of incident indicates an active attack chain targeting host WORKSTATION-089. An encoded PowerShell script was spawned via Word attachment, executed LSASS memory dump via comsvcs.dll, and established egress C2 beaconing to 198.51.100.44.`,
    findings: [
      'Initial Access: Phishing link http://phish-payroll-update.net delivered via email.',
      'Execution: powershell.exe -Enc command downloaded payload from 198.51.100.44.',
      'Credential Access: rundll32.exe comsvcs.dll MiniDump called against lsass.exe.',
      'Command & Control: Outbound TLS session active on port 443 with self-signed certificate.',
    ],
    mitre_mappings: [
      { technique_id: 'T1059.001', technique_name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution', confidence: 0.98, evidence_snippet: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFA...' },
      { technique_id: 'T1003.001', technique_name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access', confidence: 0.95, evidence_snippet: 'rundll32.exe comsvcs.dll MiniDump 672 C:\\Windows\\Temp\\lsass.dmp' },
      { technique_id: 'T1071.001', technique_name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control', confidence: 0.92, evidence_snippet: 'Outbound socket connection to 198.51.100.44:443' },
    ],
    cited_evidence: [
      { citation_id: 'cit_01', source_type: 'alert', source_id: 'alt_sim_002', title: 'LSASS Memory Dump Alert', snippet: 'Process comsvcs.dll attempted minidump of lsass.exe process memory.', relevance_score: 0.96 },
      { citation_id: 'cit_02', source_type: 'knowledge_base', source_id: 'kb_lsass_playbook', title: 'LSASS Dumping Containment Playbook', snippet: 'Isolate host immediately and verify if LSASS credentials were compromised.', relevance_score: 0.91 },
      { citation_id: 'cit_03', source_type: 'indicator', source_id: 'ind_001', title: 'Threat Intel: 198.51.100.44', snippet: 'High risk C2 node associated with Cobalt Strike infrastructure.', relevance_score: 0.89 },
    ],
    recommendations: [
      { category: 'response', title: 'Isolate Host WORKSTATION-089', description: 'Sever network connection via EDR agent.', priority: 'high', requires_approval: true },
      { category: 'response', title: 'Reset Credentials for victim.user@enterprise.com', description: 'Force password reset and revoke active tokens.', priority: 'high', requires_approval: true },
      { category: 'investigative', title: 'Scan Enterprise Host Memory', description: 'Search surrounding host endpoints for indicator 198.51.100.44.', priority: 'medium', requires_approval: false },
    ],
    confidence: 0.94,
    limitations: [
      'No host memory dump payload artifact was uploaded for static reverse engineering.',
      'Active network session packet payload is encrypted (TLS 1.3).',
    ],
    timestamp: new Date().toISOString(),
  });
}

export async function getMitreMatrix() {
  return fetchAPI('/mitre/matrix', { method: 'GET' }, {
    tactics: [
      { id: 'TA0001', name: 'Initial Access', count: 2, techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', observed_count: 1 }] },
      { id: 'TA0002', name: 'Execution', count: 4, techniques: [{ id: 'T1059.001', name: 'PowerShell', observed_count: 3 }] },
      { id: 'TA0006', name: 'Credential Access', count: 3, techniques: [{ id: 'T1003.001', name: 'LSASS Memory Dump', observed_count: 2 }] },
      { id: 'TA0011', name: 'Command and Control', count: 5, techniques: [{ id: 'T1071.001', name: 'Web Protocols', observed_count: 4 }] },
    ]
  });
}

export async function enrichIndicator(value: string) {
  return fetchAPI<IndicatorItem>(`/indicators/enrich`, {
    method: 'POST',
    body: JSON.stringify({ indicator_value: value }),
  }, {
    id: `ind_${Math.random().toString(36).substring(2, 8)}`,
    indicator_value: value,
    indicator_type: value.includes('.') && !value.match(/[a-z]/i) ? 'ip' : (value.includes('.') ? 'domain' : 'file_hash'),
    reputation_score: 91.5,
    risk_level: 'high',
    threat_actor: 'APT-29 / Cobalt Strike Infrastructure',
    source_attribution: 'VirusTotal / AlienVault OTX / CrowdStrike Mock',
    confidence: 0.95,
    created_at: new Date().toISOString(),
    raw_enrichment: {
      positives: 48,
      total_engines: 72,
      country: 'RU',
      asn: 'AS48322',
      tags: ['c2', 'cobalt-strike', 'malware-delivery'],
    }
  });
}
