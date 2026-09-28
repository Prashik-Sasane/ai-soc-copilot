'use client';

import React, { useState } from 'react';
import { Search, ShieldAlert, Globe, Server, Hash, Activity } from 'lucide-react';
import { enrichIndicator, IndicatorItem } from '@/lib/api';

export default function IndicatorsPage() {
  const [searchValue, setSearchValue] = useState('198.51.100.44');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IndicatorItem | null>(null);

  const handleEnrich = async (val?: string) => {
    const target = val || searchValue;
    if (!target.trim()) return;

    setLoading(true);
    try {
      const data = await enrichIndicator(target);
      setResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Search className="w-6 h-6 text-cyan-400" />
          <span>Threat Intelligence & Indicator Enrichment</span>
        </h1>
        <p className="text-sm text-soc-textMuted mt-1">
          Query IP addresses, domains, and file hashes against threat intelligence aggregators.
        </p>
      </div>

      {/* Search form */}
      <div className="glass-panel p-5 rounded-2xl border border-soc-cardBorder space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleEnrich();
          }}
          className="flex gap-3"
        >
          <div className="relative flex-1">
            <Globe className="w-4 h-4 absolute left-3.5 top-3.5 text-soc-textMuted" />
            <input
              type="text"
              placeholder="Enter IP (e.g. 198.51.100.44), Domain (c2-command-node.ru), or MD5/SHA256 Hash..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-soc-sidebar border border-soc-cardBorder rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !searchValue.trim()}
            className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm transition-all disabled:opacity-50 shrink-0"
          >
            {loading ? 'Querying Intel...' : 'Enrich Indicator'}
          </button>
        </form>

        <div className="flex items-center space-x-2 text-xs text-soc-textMuted">
          <span>Try Sample IOCs:</span>
          <button
            onClick={() => {
              setSearchValue('198.51.100.44');
              handleEnrich('198.51.100.44');
            }}
            className="text-cyan-400 hover:underline font-mono"
          >
            198.51.100.44
          </button>
          <span>•</span>
          <button
            onClick={() => {
              setSearchValue('c2-command-node.ru');
              handleEnrich('c2-command-node.ru');
            }}
            className="text-cyan-400 hover:underline font-mono"
          >
            c2-command-node.ru
          </button>
        </div>
      </div>

      {/* Results card */}
      {result && (
        <div className="glass-panel p-6 rounded-2xl border border-soc-cardBorder space-y-6 animate-fade-in">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-xs font-mono uppercase text-soc-textMuted">{result.indicator_type} Indicator</span>
              <h2 className="text-xl font-bold font-mono text-cyan-400">{result.indicator_value}</h2>
            </div>

            <div className="text-right">
              <span className="text-xs text-soc-textMuted block font-mono">Reputation Risk Score</span>
              <span className="text-2xl font-bold text-rose-500 font-mono">{result.reputation_score} / 100</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Threat Actor Attribution:</span>
              <div className="font-semibold text-white text-sm">{result.threat_actor || 'Unknown / Unattributed'}</div>
            </div>

            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Primary Intelligence Sources:</span>
              <div className="font-semibold text-cyan-300 text-sm">{result.source_attribution}</div>
            </div>

            <div className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder space-y-1">
              <span className="text-xs text-soc-textMuted">Attribution Confidence:</span>
              <div className="font-semibold text-emerald-400 text-sm font-mono">{Math.round(result.confidence * 100)}% Verified</div>
            </div>
          </div>

          {result.raw_enrichment && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-soc-textMuted uppercase tracking-wider">Raw Enrichment JSON Feed</h4>
              <pre className="p-4 rounded-xl bg-soc-sidebar border border-soc-cardBorder font-mono text-xs text-emerald-400 overflow-x-auto">
                {JSON.stringify(result.raw_enrichment, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
