'use client';

import React, { useEffect, useState } from 'react';
import {
  Search,
  ShieldAlert,
  Globe,
  Server,
  Hash,
  Activity,
  RefreshCw,
  Loader2,
  AlertCircle,
  Database,
  Sparkles
} from 'lucide-react';
import {
  enrichIndicator,
  getIndicators,
  enrichIndicator as enrichIndicatorAPI,
  IndicatorItem
} from '@/lib/api';

const riskStyles: Record<string, string> = {
  critical: 'bg-rose-950/40 border-rose-800/40 text-rose-200',
  high: 'bg-amber-950/40 border-amber-800/40 text-amber-200',
  medium: 'bg-cyan-950/40 border-cyan-800/40 text-cyan-200',
  low: 'bg-emerald-950/40 border-emerald-800/40 text-emerald-200',
  unknown: 'bg-soc-sidebar/80 border-soc-cardBorder text-soc-textMuted',
};

const sampleIOCs = [
  { value: '198.51.100.44', type: 'ip' },
  { value: 'c2-command-node.ru', type: 'domain' },
  { value: '5d41402abc4b2a76b9719d911017c592', type: 'md5' },
  { value: 'http://malware-cdn.xyz/payload.exe', type: 'url' },
];

export default function IndicatorsPage() {
  const [searchValue, setSearchValue] = useState('198.51.100.44');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IndicatorItem | null>(null);
  const [existingIndicators, setExistingIndicators] = useState<IndicatorItem[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadList = async () => {
    setListLoading(true);
    try {
      const list = await getIndicators(undefined, undefined, 50);
      setExistingIndicators(list || []);
    } catch (e: any) {
      console.error(e);
    } finally {
      setListLoading(false);
    }
  };

  useEffect(() => {
    loadList();
  }, []);

  const handleEnrich = async (val?: string) => {
    const target = val || searchValue;
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const data = await enrichIndicatorAPI(target);
      setResult(data);
      await loadList();
    } catch (e: any) {
      console.error(e);
      setError(e?.message || 'Failed to enrich indicator');
    } finally {
      setLoading(false);
    }
  };

  const inferType = (val: string): string => {
    const v = val.trim();
    if (/^(https?:\/\/)/i.test(v)) return 'url';
    if (/^[a-fA-F0-9]{32}$/.test(v) || /^[a-fA-F0-9]{40}$/.test(v) || /^[a-fA-F0-9]{64}$/.test(v)) return 'file_hash';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return 'ip';
    if (v.includes('.') && !v.includes(' ')) return 'domain';
    return 'ip';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Search className="w-6 h-6 text-cyan-400" />
            <span>Threat Intelligence & Indicator Enrichment</span>
          </h1>
          <p className="text-sm text-soc-textMuted mt-1">
            Query IP addresses, domains, URLs, and file hashes against threat intelligence aggregators.
          </p>
        </div>
        <button
          onClick={loadList}
          disabled={listLoading}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-soc-sidebar border border-soc-cardBorder text-soc-textMuted hover:text-white hover:border-cyan-500/50 transition-all text-xs font-medium disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${listLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Search form */}
      <div className="glass-panel p-5 rounded-2xl border border-soc-cardBorder space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleEnrich();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Globe className="w-4 h-4 absolute left-3.5 top-3.5 text-soc-textMuted" />
            <input
              type="text"
              placeholder="Enter IP (e.g. 198.51.100.44), Domain (c2-command-node.ru), URL, or MD5/SHA256 Hash..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !searchValue.trim()}
            className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm transition-all disabled:opacity-50 shrink-0 inline-flex items-center justify-center gap-2"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4" />
            )}
            {loading ? 'Querying Intel...' : 'Enrich Indicator'}
          </button>
        </form>

        <div className="flex items-center gap-2 text-xs text-soc-textMuted flex-wrap">
          <span>Try Sample IOCs:</span>
          {sampleIOCs.map((s) => (
            <button
              key={s.value}
              onClick={() => {
                setSearchValue(s.value);
                handleEnrich(s.value);
              }}
              className="px-2.5 py-1 rounded-lg bg-soc-sidebar border border-soc-cardBorder hover:border-cyan-500/50 text-cyan-400 hover:text-cyan-300 font-mono transition-all"
            >
              {s.value.length > 24 ? s.value.slice(0, 24) + '...' : s.value}
            </button>
          ))}
        </div>

        {error && (
          <div className="p-3 rounded-xl border border-rose-800/50 bg-rose-950/20 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <p className="text-xs text-rose-200/80">{error}</p>
          </div>
        )}
      </div>

      {/* Results card */}
      {result && (
        <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-6 animate-fade-in">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="space-y-1 flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono uppercase text-soc-textMuted px-2 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder">
                  {result.indicator_type} Indicator
                </span>
                <span
                  className={`px-2 py-0.5 rounded border text-xs font-mono ${
                    riskStyles[result.risk_level] || riskStyles.unknown
                  }`}
                >
                  Risk: {result.risk_level?.toUpperCase() || 'UNKNOWN'}
                </span>
              </div>
              <h2 className="text-xl font-bold font-mono text-cyan-400 break-all leading-snug">
                {result.indicator_value}
              </h2>
            </div>

            <div className="text-right shrink-0">
              <span className="text-xs text-soc-textMuted block font-mono">Reputation Risk Score</span>
              <div className="flex items-baseline gap-1 justify-end">
                <span
                  className={`text-3xl font-bold font-mono ${
                    result.reputation_score >= 80
                      ? 'text-rose-500'
                      : result.reputation_score >= 50
                      ? 'text-amber-400'
                      : result.reputation_score >= 20
                      ? 'text-cyan-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {result.reputation_score}
                </span>
                <span className="text-sm text-soc-textMuted font-mono"> / 100</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Threat Actor Attribution:</span>
              <div className="font-semibold text-white text-sm">
                {result.threat_actor || 'Unknown / Unattributed'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Primary Intelligence Sources:</span>
              <div className="font-semibold text-cyan-300 text-sm">
                {result.source_attribution || 'Local Mock Feed'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Attribution Confidence:</span>
              <div className="font-semibold text-emerald-400 text-sm font-mono">
                {Math.round((result.confidence || 0) * 100)}% Verified
              </div>
            </div>
          </div>

          {result.raw_enrichment && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-soc-textMuted uppercase tracking-wider">
                Raw Enrichment JSON Feed
              </h4>
              <pre className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder font-mono text-xs text-emerald-400 overflow-x-auto max-h-64 overflow-y-auto">
                {JSON.stringify(result.raw_enrichment, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Existing Indicators */}
      <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
            <Database className="w-5 h-5 text-purple-400" />
            <span>Enriched Indicator History</span>
          </h2>
          <span className="px-2.5 py-0.5 rounded bg-soc-sidebar border border-soc-cardBorder text-xs font-mono text-purple-400">
            {existingIndicators.length} Indicators
          </span>
        </div>

        {listLoading ? (
          <div className="flex items-center justify-center py-12 text-soc-textMuted text-xs font-mono">
            <Loader2 className="w-4 h-4 animate-spin mr-2" />
            Loading indicator history...
          </div>
        ) : existingIndicators.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Database className="w-10 h-10 text-soc-textMuted/50 mx-auto" />
            <p className="text-sm text-soc-textMuted italic">
              No indicators enriched yet. Query some IOCs above to build your threat intel library.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-soc-sidebar/80 border-b border-soc-cardBorder font-mono uppercase text-soc-textMuted text-[10px]">
                  <th className="py-2.5 px-3">Indicator Value</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Risk Level</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Threat Actor</th>
                  <th className="py-2.5 px-3">Source</th>
                  <th className="py-2.5 px-3">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-cardBorder">
                {existingIndicators.map((ind) => (
                  <tr
                    key={ind.id}
                    className="hover:bg-soc-hover/50 cursor-pointer"
                    onClick={() => {
                      setSearchValue(ind.indicator_value);
                      handleEnrich(ind.indicator_value);
                    }}
                  >
                    <td className="py-2.5 px-3 font-mono text-cyan-300 break-all max-w-[240px]">
                      {ind.indicator_value}
                    </td>
                    <td className="py-2.5 px-3 font-mono uppercase text-soc-textMuted">
                      {ind.indicator_type}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded border text-[10px] font-mono ${
                          riskStyles[ind.risk_level] || riskStyles.unknown
                        }`}
                      >
                        {ind.risk_level?.toUpperCase() || 'UNKNOWN'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono font-bold">{ind.reputation_score}/100</td>
                    <td className="py-2.5 px-3 text-white">
                      {ind.threat_actor || <span className="text-soc-textMuted/60 italic">—</span>}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-soc-textMuted">
                      {ind.source_attribution?.slice(0, 24) || '—'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-soc-textMuted whitespace-nowrap">
                      {new Date(ind.last_seen || ind.updated_at || ind.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
