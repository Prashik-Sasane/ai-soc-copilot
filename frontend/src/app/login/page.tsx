'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldAlert, Lock, Mail, ArrowRight, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';
import { AuthResponse, completeLoginMfaSetup, completeMfaLogin, isAuthenticated, loginUser, MfaSetupResponse, startLoginMfaSetup } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaSetupToken, setMfaSetupToken] = useState<string | null>(null);
  const [mfaSetup, setMfaSetup] = useState<MfaSetupResponse | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [pendingSession, setPendingSession] = useState<{ access_token: string; user: NonNullable<AuthResponse['user']> } | null>(null);

  useEffect(() => {
    if (isAuthenticated()) {
      router.push('/');
    }
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const res = mfaSetupToken
        ? await completeLoginMfaSetup(mfaSetupToken, mfaCode)
        : mfaToken
          ? await completeMfaLogin(mfaToken, mfaCode)
          : await loginUser(email, password);
      if (res.mfa_setup_required && res.mfa_token) {
        setMfaSetupToken(res.mfa_token);
        setMfaSetup(await startLoginMfaSetup(res.mfa_token));
        setSuccess('Password accepted. Scan the QR code with your authenticator app, then enter its current code to finish sign-in.');
        setLoading(false);
        return;
      }
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setSuccess('Password accepted. Enter the current code from your authenticator app or a recovery code.');
        setLoading(false);
        return;
      }
      if (!res.access_token || !res.user) throw new Error('Sign-in did not return an access token.');
      setMfaToken(null);
      setMfaSetupToken(null);
      setMfaSetup(null);
      setMfaCode('');
      setSuccess(`Authenticated successfully as ${res.user.role.toUpperCase()} (${res.user.email})`);
      if (res.recovery_codes?.length) {
        setRecoveryCodes(res.recovery_codes);
        setPendingSession({ access_token: res.access_token, user: res.user });
        return;
      }
      localStorage.setItem('soc_token', res.access_token);
      localStorage.setItem('soc_user', JSON.stringify(res.user));
      setTimeout(() => {
        router.push('/');
      }, 1000);
    } catch (err: any) {
      setError(err?.message || (mfaSetupToken || mfaToken ? 'Invalid authenticator code.' : 'Invalid email or password credentials.'));
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFillAdmin = () => {
    setEmail('admin@aisoc.io');
    setPassword('AdminSOC123!');
  };

  const handleDemoFillAnalyst = () => {
    setEmail('analyst@aisoc.io');
    setPassword('AnalystSOC123!');
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full glass-panel p-8 rounded-3xl border border-soc-cardBorder space-y-6 shadow-cyan-glow relative overflow-hidden">
        <div className="absolute -top-12 -left-12 w-36 h-36 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-12 -right-12 w-36 h-36 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-cyan-glow mx-auto">
            <ShieldAlert className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">SOC Analyst Portal</h1>
          <p className="text-xs text-soc-textMuted">{mfaSetupToken ? 'Set up your required second factor' : mfaToken ? 'Two-factor verification' : 'Authenticate to access enterprise threat intelligence & RAG copilot'}</p>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800/60 text-rose-300 text-xs flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 text-xs flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {!mfaToken && !mfaSetupToken && <>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
              <Mail className="w-3.5 h-3.5 text-cyan-400" />
              <span>Analyst Email</span>
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@enterprise.com"
              className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Password</span>
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          </>}

          {mfaSetupToken && mfaSetup && (
            <div className="space-y-3 rounded-xl border border-cyan-800/50 bg-soc-sidebar p-4">
              <p className="text-xs text-white">Scan this QR code using Google Authenticator or another TOTP app. Setup expires at {new Date(mfaSetup.expires_at).toLocaleTimeString()}.</p>
              <img src={mfaSetup.qr_code_data_uri} alt="Authenticator enrollment QR code" className="w-48 h-48 bg-white rounded-lg p-2 mx-auto" />
              <details>
                <summary className="cursor-pointer text-xs text-cyan-300">Can’t scan? Show setup URI</summary>
                <code className="block mt-2 break-all text-[10px] text-white">{mfaSetup.otpauth_uri}</code>
              </details>
            </div>
          )}
          {mfaSetupToken && !mfaSetup && (
            <button type="button" onClick={async () => {
              setLoading(true); setError(null);
              try { setMfaSetup(await startLoginMfaSetup(mfaSetupToken)); }
              catch (e: any) { setError(e?.message || 'Unable to load the authenticator QR code.'); }
              finally { setLoading(false); }
            }} className="text-xs text-cyan-300 underline">Retry loading authenticator QR code</button>
          )}

          {(mfaToken || mfaSetupToken) && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                <span>{mfaSetupToken ? 'Authenticator code to finish setup' : 'Authenticator code or recovery code'}</span>
              </label>
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.trim())}
                placeholder="123456"
                className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500 font-mono tracking-widest"
              />
              <button type="button" onClick={() => { setMfaToken(null); setMfaSetupToken(null); setMfaSetup(null); setMfaCode(''); setError(null); setSuccess(null); }} className="text-xs text-cyan-400 underline">Back to password</button>
            </div>
          )}

          <div className="pt-2 space-y-3">
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 py-3 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-medium text-xs shadow-cyan-glow transition-all active:scale-95 disabled:opacity-50"
            >
              <span>{loading ? 'Authenticating...' : mfaSetupToken ? 'Verify code & finish setup' : mfaToken ? 'Verify & Sign In' : 'Sign In to SOC Workspace'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            {!mfaToken && !mfaSetupToken && <div className="flex gap-2">
              <button
                type="button"
                onClick={handleDemoFillAdmin}
                className="flex-1 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder hover:border-cyan-500/40 text-soc-textMuted hover:text-cyan-400 text-xs font-mono transition-all flex items-center justify-center space-x-1"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Admin Demo</span>
              </button>
              <button
                type="button"
                onClick={handleDemoFillAnalyst}
                className="flex-1 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder hover:border-purple-500/40 text-soc-textMuted hover:text-purple-400 text-xs font-mono transition-all flex items-center justify-center space-x-1"
              >
                <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                <span>Analyst Demo</span>
              </button>
            </div>}
          </div>
        </form>

        {recoveryCodes.length > 0 && (
          <div className="rounded-xl border border-amber-700/60 bg-amber-950/30 p-4 space-y-2">
            <h2 className="text-sm font-semibold text-amber-200">Save your one-time recovery codes</h2>
            <p className="text-xs text-amber-100/80">These are shown once. Store them securely; each code can be used only one time.</p>
            <div className="grid grid-cols-2 gap-2 font-mono text-xs text-white">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div>
            <button type="button" onClick={() => navigator.clipboard?.writeText(recoveryCodes.join('\n'))} className="text-xs text-cyan-300 underline">Copy recovery codes</button>
            <button type="button" onClick={() => {
              if (pendingSession) {
                localStorage.setItem('soc_token', pendingSession.access_token);
                localStorage.setItem('soc_user', JSON.stringify(pendingSession.user));
              }
              router.push('/');
            }} className="block w-full px-3 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-medium">I saved my recovery codes — continue</button>
          </div>
        )}

        <div className="pt-4 border-t border-soc-cardBorder text-center text-xs text-soc-textMuted">
          Need an analyst account?{' '}
          <Link href="/register" className="text-cyan-400 hover:text-cyan-300 font-semibold underline">
            Register New Analyst
          </Link>
        </div>
      </div>
    </div>
  );
}
