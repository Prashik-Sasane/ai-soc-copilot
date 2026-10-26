'use client';

import React, { useEffect, useState } from 'react';
import { AlertCircle, CheckCircle2, KeyRound, ShieldCheck } from 'lucide-react';
import { disableMfa, enableMfa, getMfaStatus, startMfaSetup, clearAuth, MfaSetupResponse } from '@/lib/api';

export default function SecuritySettingsPage() {
  const [enabled, setEnabled] = useState(false);
  const [setup, setSetup] = useState<MfaSetupResponse | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refreshStatus = async () => {
    const result = await getMfaStatus();
    setEnabled(result.enabled);
  };

  useEffect(() => {
    refreshStatus().catch((e: any) => setError(e?.message || 'Unable to load security status.'));
  }, []);

  const beginSetup = async () => {
    setLoading(true); setError(null); setMessage(null);
    try { setSetup(await startMfaSetup()); }
    catch (e: any) { setError(e?.message || 'Unable to start MFA setup.'); }
    finally { setLoading(false); }
  };

  const confirmSetup = async (event: React.FormEvent) => {
    event.preventDefault(); setLoading(true); setError(null);
    try {
      const result = await enableMfa(code);
      setEnabled(result.enabled); setRecoveryCodes(result.recovery_codes); setSetup(null); setCode('');
      setMessage('MFA is enabled. Save these recovery codes somewhere secure; they are shown only once.');
    } catch (e: any) { setError(e?.message || 'The code was rejected. Check your device time and try again.'); }
    finally { setLoading(false); }
  };

  const turnOff = async (event: React.FormEvent) => {
    event.preventDefault(); setLoading(true); setError(null);
    try {
      await disableMfa(password, code);
      setMessage('MFA disabled and all existing sessions revoked. Sign in again.');
      clearAuth();
      window.location.assign('/login');
    } catch (e: any) { setError(e?.message || 'Unable to disable MFA.'); }
    finally { setLoading(false); }
  };

  return (
    <main className="max-w-3xl mx-auto space-y-6">
      <header className="flex items-center gap-3">
        <ShieldCheck className="w-8 h-8 text-cyan-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">Account Security</h1>
          <p className="text-sm text-soc-textMuted">Protect your AI SOC Copilot account with an authenticator app.</p>
        </div>
      </header>

      {error && <div role="alert" className="p-3 rounded-xl bg-rose-950/60 border border-rose-800/60 text-rose-300 text-sm flex gap-2"><AlertCircle className="w-4 h-4 shrink-0" />{error}</div>}
      {message && <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 text-sm flex gap-2"><CheckCircle2 className="w-4 h-4 shrink-0" />{message}</div>}

      <section className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="font-semibold text-white">Authenticator app (TOTP)</h2>
            <p className="text-xs text-soc-textMuted mt-1">Works with Google Authenticator and other TOTP apps.</p>
          </div>
          <span className={`text-xs px-2 py-1 rounded border ${enabled ? 'text-emerald-300 border-emerald-700 bg-emerald-950/40' : 'text-amber-300 border-amber-700 bg-amber-950/40'}`}>
            {enabled ? 'Enabled' : 'Not enabled'}
          </span>
        </div>

        {!enabled && !setup && (
          <button disabled={loading} onClick={beginSetup} className="px-4 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm">
            {loading ? 'Preparing setup…' : 'Set up authenticator'}
          </button>
        )}

        {!enabled && setup && (
          <div className="grid md:grid-cols-2 gap-6 items-start pt-2">
            <div className="space-y-2 text-sm text-soc-textMuted">
              <p>1. Open Google Authenticator (or another TOTP app).</p>
              <p>2. Scan this QR code. Setup expires at {new Date(setup.expires_at).toLocaleTimeString()}.</p>
              <img src={setup.qr_code_data_uri} alt="Authenticator enrollment QR code" className="w-52 h-52 bg-white rounded-lg p-2" />
              <details>
                <summary className="cursor-pointer text-cyan-300">Can’t scan? Show setup URI</summary>
                <code className="block mt-2 break-all text-[10px] text-white">{setup.otpauth_uri}</code>
              </details>
            </div>
            <form onSubmit={confirmSetup} className="space-y-3">
              <label className="block text-xs text-soc-textMuted">Enter the 6-digit code shown in the app</label>
              <input required minLength={6} maxLength={6} inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} className="w-full px-3 py-2 bg-soc-sidebar border border-soc-cardBorder rounded-lg text-white font-mono tracking-widest" placeholder="123456" />
              <button disabled={loading || code.length !== 6} className="px-4 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm">{loading ? 'Verifying…' : 'Verify and enable MFA'}</button>
            </form>
          </div>
        )}

        {enabled && (
          <form onSubmit={turnOff} className="border-t border-soc-cardBorder pt-4 space-y-3">
            <p className="text-xs text-soc-textMuted">To disable MFA, confirm your password and a current authenticator or unused recovery code. Disabling revokes current sessions.</p>
            <input required type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full px-3 py-2 bg-soc-sidebar border border-soc-cardBorder rounded-lg text-white" placeholder="Current password" />
            <input required minLength={6} maxLength={20} value={code} onChange={(e) => setCode(e.target.value.trim())} className="w-full px-3 py-2 bg-soc-sidebar border border-soc-cardBorder rounded-lg text-white font-mono" placeholder="Authenticator or recovery code" />
            <button disabled={loading} className="px-4 py-2 rounded-lg bg-rose-800 hover:bg-rose-700 disabled:opacity-50 text-white text-sm">Disable MFA</button>
          </form>
        )}

        {recoveryCodes.length > 0 && (
          <div className="rounded-xl border border-amber-700/60 bg-amber-950/30 p-4 space-y-2">
            <h3 className="text-sm font-semibold text-amber-200 flex items-center gap-2"><KeyRound className="w-4 h-4" />Recovery codes</h3>
            <p className="text-xs text-amber-100/80">Each code works once. Store these securely; the server stores only hashes.</p>
            <div className="grid grid-cols-2 gap-2 font-mono text-sm text-white">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div>
            <button type="button" onClick={() => navigator.clipboard?.writeText(recoveryCodes.join('\n'))} className="text-xs text-cyan-300 underline">Copy recovery codes</button>
          </div>
        )}
      </section>
    </main>
  );
}
