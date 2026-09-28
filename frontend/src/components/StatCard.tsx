import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'cyan' | 'rose' | 'amber' | 'emerald' | 'purple';
}

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan' }: StatCardProps) {
  const colorStyles = {
    cyan: 'from-cyan-500/10 to-blue-500/5 text-cyan-400 border-cyan-500/20 shadow-cyan-glow',
    rose: 'from-rose-500/10 to-red-500/5 text-rose-400 border-rose-500/20 shadow-rose-glow',
    amber: 'from-amber-500/10 to-orange-500/5 text-amber-400 border-amber-500/20 shadow-amber-glow',
    emerald: 'from-emerald-500/10 to-green-500/5 text-emerald-400 border-emerald-500/20 shadow-emerald-glow',
    purple: 'from-purple-500/10 to-indigo-500/5 text-purple-400 border-purple-500/20 shadow-purple-glow',
  };

  return (
    <div className={`glass-panel p-5 rounded-2xl border bg-gradient-to-br transition-all hover:scale-[1.02] ${colorStyles[color]}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-soc-textMuted uppercase tracking-wider">{title}</span>
        <div className="w-9 h-9 rounded-xl bg-soc-card/80 flex items-center justify-center border border-soc-cardBorder">
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="mt-3">
        <div className="text-2xl font-bold text-white tracking-tight">{value}</div>
        {subtitle && <p className="text-xs text-soc-textMuted mt-1 font-mono">{subtitle}</p>}
      </div>
    </div>
  );
}
