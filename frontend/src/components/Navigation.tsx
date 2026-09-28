'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  ShieldAlert,
  LayoutDashboard,
  AlertTriangle,
  Flame,
  Bot,
  Grid,
  Search,
  BookOpen,
  Zap,
  LogOut,
  User as UserIcon,
  CheckCircle2,
} from 'lucide-react';
import { triggerSyntheticScenario, getCurrentUser, clearAuth, UserItem } from '@/lib/api';

export default function Navigation() {
  const pathname = usePathname();
  const router = useRouter();
  const [isSimulating, setIsSimulating] = useState(false);
  const [simMessage, setSimMessage] = useState<string | null>(null);
  const [user, setUser] = useState<UserItem | null>(null);

  useEffect(() => {
    setUser(getCurrentUser());
  }, [pathname]);

  const navItems = [
    { label: 'SOC Dashboard', href: '/', icon: LayoutDashboard },
    { label: 'Alert Triage', href: '/alerts', icon: AlertTriangle },
    { label: 'Incidents Workspace', href: '/incidents', icon: Flame },
    { label: 'AI Copilot RAG', href: '/copilot', icon: Bot },
    { label: 'MITRE ATT&CK', href: '/mitre', icon: Grid },
    { label: 'Threat Intel Lookup', href: '/indicators', icon: Search },
    { label: 'Knowledge & Audit', href: '/knowledge', icon: BookOpen },
  ];

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimMessage(null);
    try {
      const res = await triggerSyntheticScenario();
      setSimMessage('Attack Scenario Ingested!');
      setTimeout(() => setSimMessage(null), 4000);
    } catch (e: any) {
      setSimMessage(e?.message || 'Scenario trigger requested');
      setTimeout(() => setSimMessage(null), 3000);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleLogout = () => {
    clearAuth();
    router.push('/login');
  };

  const roleLabel = (role?: string) => {
    switch (role) {
      case 'admin': return 'SOC Admin';
      case 'analyst': return 'SOC Analyst';
      case 'viewer': return 'Read-Only Viewer';
      default: return 'SOC Analyst';
    }
  };

  const roleColor = (role?: string) => {
    switch (role) {
      case 'admin': return 'text-rose-400';
      case 'analyst': return 'text-cyan-400';
      case 'viewer': return 'text-emerald-400';
      default: return 'text-cyan-400';
    }
  };

  return (
    <>
      {/* Top Header Navbar */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-soc-sidebar/90 backdrop-blur-md border-b border-soc-cardBorder z-50 flex items-center justify-between px-6">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-cyan-glow">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-wide text-white">AI SOC COPILOT</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-700/50 font-mono">v1.0 enterprise</span>
            </div>
            <p className="text-xs text-soc-textMuted">Evidence-Grounded Autonomous Threat Triage & RAG System</p>
          </div>
        </div>

        {/* Action Controls & Live Status */}
        <div className="flex items-center space-x-4">
          {simMessage && (
            <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 text-xs animate-fade-in font-medium">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>{simMessage}</span>
            </div>
          )}

          <button
            onClick={handleSimulate}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs shadow-cyan-glow transition-all active:scale-95 disabled:opacity-50"
          >
            <Zap className={`w-4 h-4 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'Injecting Attack...' : 'Simulate Attack Scenario'}</span>
          </button>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-soc-card border border-soc-cardBorder text-xs text-soc-textMuted">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-mono text-emerald-400">SOC Telemetry: Active</span>
          </div>

          {/* User Profile & Logout */}
          <div className="flex items-center space-x-3 pl-3 border-l border-soc-cardBorder">
            <div className="text-right">
              <div className="text-xs font-semibold text-white flex items-center justify-end gap-1">
                <UserIcon className="w-3.5 h-3.5 text-purple-400" />
                <span>{user?.full_name || user?.email?.split('@')[0] || 'Analyst'}</span>
              </div>
              <div className={`text-[10px] font-mono ${roleColor(user?.role)}`}>
                {roleLabel(user?.role)}
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 rounded-lg bg-soc-card border border-soc-cardBorder text-soc-textMuted hover:text-rose-400 hover:border-rose-800/50 transition-all"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Sidebar Navigation */}
      <aside className="fixed top-16 left-0 bottom-0 w-64 bg-soc-sidebar border-r border-soc-cardBorder z-40 p-4 flex flex-col justify-between">
        <div className="space-y-1">
          <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-soc-textMuted">
            Investigation Modules
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${isActive
                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-cyan-glow'
                    : 'text-soc-textMuted hover:text-white hover:bg-soc-hover'
                  }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-soc-textMuted'}`} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </div>

        {/* Tenant Footer Info */}
        <div className="p-3.5 rounded-xl bg-soc-card border border-soc-cardBorder space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-soc-textMuted">Tenant:</span>
            <span className="font-mono text-cyan-400">{user?.tenant_id || 'tenant_default'}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-soc-textMuted">Role:</span>
            <span className={`font-medium ${roleColor(user?.role)}`}>{roleLabel(user?.role)}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-soc-textMuted">RAG Engine:</span>
            <span className="text-emerald-400 font-mono">LangGraph + pgvector</span>
          </div>
        </div>
      </aside>
    </>
  );
}
