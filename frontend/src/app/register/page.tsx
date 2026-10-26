'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { ShieldAlert, User, Mail, Lock, ShieldCheck, ArrowRight, CheckCircle2, AlertCircle, LogIn } from 'lucide-react';
import { registerUser, loginUser, clearAuth } from '@/lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [autoLogin, setAutoLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const passwordClasses = [/[a-z]/.test(password), /[A-Z]/.test(password), /[0-9]/.test(password), /[^A-Za-z0-9\s]/.test(password)].filter(Boolean).length;
  const passwordStrength = !password ? null : password.length < 12 || passwordClasses < 2 ? 'weak' : password.length >= 16 && passwordClasses >= 3 ? 'strong' : 'medium';

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('soc_token');
      if (token) {
        router.push('/');
      }
    }
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    if (passwordStrength === 'weak') {
      setError('Use at least 12 characters and at least two character types.');
      return;
    }
    setLoading(true);

    try {
      await registerUser(email, password, fullName, 'analyst');
      setSuccess('Analyst account created successfully!');

      if (autoLogin) {
        setTimeout(async () => {
          try {
            clearAuth();
            const loginRes = await loginUser(email, password);
            if (!loginRes.access_token || !loginRes.user) throw new Error('Complete MFA to sign in.');
            localStorage.setItem('soc_token', loginRes.access_token);
            localStorage.setItem('soc_user', JSON.stringify(loginRes.user));
            setSuccess(`Authenticated as ${loginRes.user.role.toUpperCase()} - Redirecting to SOC workspace...`);
            setTimeout(() => {
              router.push('/');
            }, 800);
          } catch (loginErr: any) {
            setSuccess('Account created! Redirecting to login page...');
            setTimeout(() => {
              router.push('/login');
            }, 1500);
          }
        }, 600);
      } else {
        setTimeout(() => {
          router.push('/login');
        }, 2000);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to register account. User may already exist.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full glass-panel p-8 rounded-3xl border border-soc-cardBorder space-y-6 shadow-purple-glow relative overflow-hidden">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-600 flex items-center justify-center shadow-purple-glow mx-auto">
            <ShieldCheck className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Create Analyst Account</h1>
          <p className="text-xs text-soc-textMuted">Register to obtain RBAC authorized access to SOC Telemetry</p>
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
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
              <User className="w-3.5 h-3.5 text-purple-400" />
              <span>Full Name</span>
            </label>
            <input
              type="text"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Analyst Security Lead"
              className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
              <Mail className="w-3.5 h-3.5 text-purple-400" />
              <span>Analyst Email</span>
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="new.analyst@enterprise.com"
              className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-soc-textMuted flex items-center space-x-1">
              <Lock className="w-3.5 h-3.5 text-purple-400" />
              <span>Password (at least 12 characters)</span>
            </label>
            <input
              type="password"
              required
              minLength={12}
              maxLength={72}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-4 py-2.5 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
            />
            {password && (
              <div aria-live="polite" className="space-y-1 pt-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-soc-textMuted">Password strength</span>
                  <span className={passwordStrength === 'strong' ? 'text-emerald-400' : passwordStrength === 'medium' ? 'text-amber-300' : 'text-rose-400'}>
                    {passwordStrength?.toUpperCase()}
                  </span>
                </div>
                <div className="h-1.5 rounded bg-soc-card overflow-hidden">
                  <div className={`h-full transition-all ${passwordStrength === 'strong' ? 'w-full bg-emerald-500' : passwordStrength === 'medium' ? 'w-2/3 bg-amber-400' : 'w-1/3 bg-rose-500'}`} />
                </div>
                <p className="text-[10px] text-soc-textMuted">Strength uses length and lowercase, uppercase, number, and symbol variety. Passwords are never sent to an external strength service.</p>
              </div>
            )}
          </div>

          <div className="flex items-center space-x-2 text-xs text-soc-textMuted">
            <input
              type="checkbox"
              id="autoLogin"
              checked={autoLogin}
              onChange={(e) => setAutoLogin(e.target.checked)}
              className="w-3.5 h-3.5 rounded bg-soc-sidebar border-soc-cardBorder text-purple-600 focus:ring-purple-500"
            />
            <label htmlFor="autoLogin" className="cursor-pointer select-none">Automatically sign-in after registration</label>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 py-3 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-medium text-xs shadow-purple-glow transition-all active:scale-95 disabled:opacity-50"
            >
              <span>{loading ? 'Creating Account & Authenticating...' : 'Register & Access SOC'}</span>
              {loading ? <CheckCircle2 className="w-4 h-4 animate-pulse" /> : <><LogIn className="w-4 h-4" /><ArrowRight className="w-4 h-4" /></>}
            </button>
          </div>
        </form>

        <div className="pt-4 border-t border-soc-cardBorder text-center text-xs text-soc-textMuted">
          Already registered?{' '}
          <Link href="/login" className="text-purple-400 hover:text-purple-300 font-semibold underline">
            Sign In to Account
          </Link>
        </div>
      </div>
    </div>
  );
}
