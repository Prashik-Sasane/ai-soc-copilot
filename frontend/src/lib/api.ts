const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export interface AlertItem {
  id: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  base_severity?: 'critical' | 'high' | 'medium' | 'low' | null;
  risk_score?: number | null;
  confidence?: number | null;
  risk_factors?: Record<string, string | number | boolean | null> | null;
  detection_rule_version?: string | null;
  status: 'new' | 'acknowledged' | 'investigating' | 'escalated' | 'dismissed' | 'resolved';
  source: string;
  rule_name?: string;
  asset_id?: string;
  assigned_to?: string;
  event_ids: string[];
  correlated_group_id?: string;
  correlation_reason?: string;
  link_reasons?: string[];
  incident_id?: string;
  is_simulated?: string;
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
  mitre_mappings?: Array<Record<string, any>>;
  severity_rationale?: string;
  affected_assets?: string[];
  affected_users?: string[];
  change_history_json?: Array<Record<string, any>>;
  is_simulated?: string;
  timeline_json: Array<{
    timestamp: string;
    kind?: 'event' | 'correlation' | 'analyst_action';
    event_type: string;
    title: string;
    description?: string;
    severity: string;
    source: string;
    event_id?: string;
    event_ids?: string[];
    alert_ids?: string[];
    occurrences?: number;
    first_seen?: string;
    last_seen?: string;
    stage?: string;
    technique_id?: string | null;
    technique_name?: string | null;
    confidence?: number | null;
    origin?: {
      source?: string;
      event_ref?: string | null;
      provider?: string | null;
      channel?: string | null;
      windows_event_id?: number | string | null;
      record_id?: string | null;
    };
    is_simulated?: string;
  }>;
  recommendations_json: Array<{
    category: 'response' | 'investigative';
    title: string;
    description: string;
    priority: 'high' | 'medium' | 'low';
    requires_approval: boolean;
    approved?: boolean;
    approved_by?: string;
    approved_at?: string;
    execution_status?: string;
  }>;
  created_at: string;
  updated_at: string;
}

export interface IndicatorItem {
  id: string;
  indicator_value: string;
  indicator_type: 'ip' | 'domain' | 'file_hash' | 'url';
  reputation_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'unknown' | 'not_found' | 'clean';
  lookup_status?: string;
  threat_actor?: string;
  provider_name?: string;
  cached_until?: string;
  source_attribution?: string;
  raw_enrichment?: any;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  created_at: string;
  updated_at?: string;
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
    confidence?: number | null;
    match_score?: number | null;
    status?: string;
    rationale?: string;
    evidence_refs?: string[];
    evidence_snippet?: string;
  }>;
  cited_evidence: Array<{
    citation_id: string;
    source_type: string;
    source_id: string;
    title: string;
    snippet: string;
    relevance_score?: number | null;
    hostname?: string | null;
    timestamp?: string | null;
    source_ref?: string | null;
    score_type?: string | null;
  }>;
  recommendations: Array<{
    category: string;
    title: string;
    description: string;
    priority: string;
    requires_approval: boolean;
    rationale?: string | null;
    evidence_refs?: string[];
    prerequisites?: string[];
    expected_outcome?: string | null;
    status?: string;
  }>;
  confidence: number;
  confidence_rationale?: string | null;
  status?: string;
  incident?: {
    alert_id?: string | null;
    incident_id?: string | null;
    hostname?: string | null;
    affected_user?: string | null;
    severity?: string | null;
    alert_status?: string | null;
  };
  executive_summary?: string | null;
  finding_details?: Array<{
    finding_id: string;
    title: string;
    status: string;
    severity?: string | null;
    description: string;
    rationale: string;
    evidence_refs: string[];
    missing_data: string[];
  }>;
  timeline?: Array<{
    timestamp?: string | null;
    title: string;
    event_type?: string | null;
    hostname?: string | null;
    user?: string | null;
    process_name?: string | null;
    command_line?: string | null;
    evidence_ref?: string | null;
  }>;
  indicators?: Array<Record<string, any>>;
  missing_data?: string[];
  sources?: Array<Record<string, any>>;
  limitations: string[];
  llm_used?: boolean;
  embedding_mode?: string;
  timestamp: string;
}

export interface UserItem {
  id: string;
  email: string;
  full_name?: string;
  role: 'admin' | 'analyst' | 'viewer';
  tenant_id: string;
  is_active: boolean;
  mfa_enabled?: boolean;
}

export interface AuthResponse {
  access_token?: string;
  token_type: string;
  user?: UserItem;
  mfa_required?: boolean;
  mfa_setup_required?: boolean;
  mfa_token?: string;
  recovery_codes?: string[];
}

export interface MfaSetupResponse {
  otpauth_uri: string;
  qr_code_data_uri: string;
  expires_at: string;
}

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('soc_token');
}

export function getCurrentUser(): UserItem | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem('soc_user');
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserItem;
  } catch {
    return null;
  }
}

export function clearAuth() {
  if (typeof window === 'undefined') return;
  localStorage.removeItem('soc_token');
  localStorage.removeItem('soc_user');
}

export function isAuthenticated(): boolean {
  return getAuthToken() !== null;
}

async function fetchAPI<T>(endpoint: string, options?: RequestInit, requiresAuth: boolean = true): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string> || {}),
  };

  if (requiresAuth) {
    const token = getAuthToken();
    if (!token) {
      throw new Error('Authentication required. Please sign in.');
    }
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearAuth();
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login') && !window.location.pathname.startsWith('/register')) {
      window.location.href = '/login';
    }
    throw new Error('Session expired. Please sign in again.');
  }

  if (!res.ok) {
    let errorMsg = `HTTP error! status: ${res.status}`;
    try {
      const errData = await res.json();
      if (errData.detail) {
        if (typeof errData.detail === 'string') {
          errorMsg = errData.detail;
        } else if (Array.isArray(errData.detail) && errData.detail.length > 0) {
          errorMsg = errData.detail.map((e: any) => e.msg || JSON.stringify(e)).join(', ');
        }
      }
    } catch {}
    throw new Error(errorMsg);
  }

  const contentType = res.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    return await res.json();
  }
  return {} as T;
}

export async function getDashboardStats() {
  return fetchAPI('/dashboard/stats', { method: 'GET' });
}

export async function triggerSyntheticScenario() {
  return fetchAPI('/events/simulate-scenario', { method: 'POST' });
}

export async function getAlerts() {
  return fetchAPI<{ items: AlertItem[]; total: number; page: number; size: number }>('/alerts', { method: 'GET' });
}

export async function updateAlertStatus(alertId: string, status: string, assignedTo?: string) {
  return fetchAPI<AlertItem>(`/alerts/${alertId}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status, assigned_to: assignedTo }),
  });
}

export async function updateIncident(incidentId: string, payload: Record<string, string>) {
  return fetchAPI<IncidentItem>(`/incidents/${incidentId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function approveIncidentRecommendation(incidentId: string, index: number) {
  return fetchAPI<IncidentItem>(`/incidents/${incidentId}/recommendations/${index}/approve`, {
    method: 'POST',
  });
}

export async function getIngestStatus() {
  return fetchAPI<any>('/ingest/status', { method: 'GET' });
}

export async function uploadKnowledgeDocument(payload: {
  title: string;
  content: string;
  category?: string;
  source_ref?: string;
  owner?: string;
  version?: string;
}) {
  return fetchAPI<KnowledgeDocument>('/knowledge', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function syncMitreAttack() {
  return fetchAPI<any>('/mitre/sync', { method: 'POST' });
}

export async function getIncidents() {
  return fetchAPI<{ items: IncidentItem[]; total: number; page: number; size: number }>('/incidents', { method: 'GET' });
}

export async function getIncidentById(incidentId: string) {
  return fetchAPI<IncidentItem>(`/incidents/${incidentId}`, { method: 'GET' });
}

export async function queryCopilot(query: string, incidentId?: string, alertId?: string): Promise<CopilotResponse> {
  return fetchAPI<CopilotResponse>('/copilot/query', {
    method: 'POST',
    body: JSON.stringify({ query, incident_id: incidentId, alert_id: alertId }),
  });
}

export async function getMitreMatrix() {
  return fetchAPI('/mitre/matrix', { method: 'GET' });
}

export async function enrichIndicator(value: string) {
  return fetchAPI<IndicatorItem>(`/indicators/enrich`, {
    method: 'POST',
    body: JSON.stringify({ indicator_value: value }),
  });
}

export async function loginUser(email: string, password: string): Promise<AuthResponse> {
  return fetchAPI<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  }, false);
}

export async function completeMfaLogin(mfaToken: string, code: string): Promise<AuthResponse> {
  return fetchAPI<AuthResponse>('/auth/login/mfa', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  }, false);
}

export async function startLoginMfaSetup(mfaToken: string): Promise<MfaSetupResponse> {
  return fetchAPI<MfaSetupResponse>('/auth/login/mfa/setup', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken }),
  }, false);
}

export async function completeLoginMfaSetup(mfaToken: string, code: string): Promise<AuthResponse> {
  return fetchAPI<AuthResponse>('/auth/login/mfa/enable', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  }, false);
}

export async function getMfaStatus(): Promise<{ enabled: boolean; setup_pending: boolean }> {
  return fetchAPI('/auth/mfa/status');
}

export async function startMfaSetup(): Promise<MfaSetupResponse> {
  return fetchAPI('/auth/mfa/setup', { method: 'POST' });
}

export async function enableMfa(code: string): Promise<{ enabled: boolean; recovery_codes: string[] }> {
  return fetchAPI('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) });
}

export async function disableMfa(password: string, code: string): Promise<{ enabled: boolean; message: string }> {
  return fetchAPI('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password, code }) });
}

export async function logoutUser(): Promise<void> {
  await fetchAPI('/auth/logout', { method: 'POST' });
}

export async function registerUser(email: string, password: string, fullName?: string, role: string = 'analyst'): Promise<UserItem> {
  return fetchAPI<UserItem>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password, full_name: fullName, role }),
  }, false);
}

export async function getCurrentUserProfile(): Promise<UserItem> {
  return fetchAPI<UserItem>('/auth/me', { method: 'GET' });
}

export interface KnowledgeDocument {
  id: string;
  title: string;
  category: string;
  source_ref?: string;
  content: string;
  status: string;
  chunk_count: string;
  owner?: string;
  version?: string;
  retrieved_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_id?: string;
  user_email?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details_json?: any;
  ip_address?: string;
}

export async function getKnowledgeDocuments(category?: string) {
  const qs = category ? `?category=${encodeURIComponent(category)}` : '';
  return fetchAPI<KnowledgeDocument[]>(`/knowledge${qs}`, { method: 'GET' });
}

export async function seedKnowledgePlaybooks() {
  return fetchAPI('/knowledge/seed-playbooks', { method: 'POST' });
}

export async function syncCisaKevCatalog(limit: number = 100) {
  return fetchAPI<{ message: string; document_id: string; source_ref: string; chunk_count: string }>(
    `/knowledge/sync-cisa-kev?limit=${limit}`,
    { method: 'POST' },
  );
}

export async function reindexKnowledgeVectors() {
  return fetchAPI<{ message: string; chunk_count: number }>('/knowledge/reindex', { method: 'POST' });
}

export async function getAuditLogs(limit: number = 50) {
  return fetchAPI<AuditLogEntry[]>(`/audit?limit=${limit}`, { method: 'GET' });
}

export async function submitFeedback(investigationId: string, rating: string, notes?: string) {
  return fetchAPI('/feedback', {
    method: 'POST',
    body: JSON.stringify({ investigation_id: investigationId, rating, notes }),
  });
}

export async function getCopilotHistory(limit: number = 20) {
  return fetchAPI<any[]>(`/copilot/history?limit=${limit}`, { method: 'GET' });
}

export async function getIndicators(indicatorType?: string, riskLevel?: string, limit: number = 50) {
  const params = new URLSearchParams();
  if (indicatorType) params.set('indicator_type', indicatorType);
  if (riskLevel) params.set('risk_level', riskLevel);
  params.set('limit', String(limit));
  return fetchAPI<IndicatorItem[]>(`/indicators?${params.toString()}`, { method: 'GET' });
}

export async function triggerCorrelation() {
  return fetchAPI('/incidents/trigger-correlation', { method: 'POST' });
}

export async function seedDemoScenario() {
  return fetchAPI('/events/seed-demo', { method: 'POST' });
}
