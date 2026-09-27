import React from 'react';
import { Globe, Lock, Unlock, Server, Hash, FileCode, CheckCircle, AlertTriangle } from 'lucide-react';
import { DomainAnalysis } from '../types';

interface DomainAnalysisCardProps {
  domainAnalysis: DomainAnalysis;
}

export const DomainAnalysisCard: React.FC<DomainAnalysisCardProps> = ({ domainAnalysis }) => {
  const isHttps = domainAnalysis.protocol.toLowerCase() === 'https';

  return (
    <div className="glass-card rounded-2xl p-6 border border-slate-800">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-2">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <h3 className="text-lg font-bold text-slate-100">
              Domain & URL Structural Architecture
            </h3>
          </div>
          <span className="inline-block mt-1 text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/50 text-cyan-300 border border-cyan-800/40">
            {domainAnalysis.analysis_type || 'Pattern-Based Domain Analysis'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {isHttps ? (
            <span className="inline-flex items-center gap-1 text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-full">
              <Lock className="w-3.5 h-3.5" /> HTTPS Encrypted
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-xs font-mono text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2.5 py-1 rounded-full">
              <Unlock className="w-3.5 h-3.5" /> HTTP (Unencrypted)
            </span>
          )}
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        {/* Protocol */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Protocol
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block">
            {domainAnalysis.protocol}
          </span>
        </div>

        {/* Hostname */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Hostname
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block truncate" title={domainAnalysis.hostname}>
            {domainAnalysis.hostname || 'None'}
          </span>
        </div>

        {/* Registered Domain */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Domain
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block truncate" title={domainAnalysis.registered_domain}>
            {domainAnalysis.registered_domain || 'None'}
          </span>
        </div>

        {/* Top-Level Domain (TLD) */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            TLD
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block">
            {domainAnalysis.tld || 'N/A'}
          </span>
        </div>

        {/* Subdomains */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Subdomain
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block truncate" title={domainAnalysis.subdomain || 'None'}>
            {domainAnalysis.subdomain || '(None / Apex Domain)'}
          </span>
        </div>

        {/* Port */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Port
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block">
            {domainAnalysis.port} {domainAnalysis.is_custom_port ? '(Custom)' : '(Standard)'}
          </span>
        </div>

        {/* Path */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 sm:col-span-2">
          <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
            Path
          </span>
          <span className="text-sm font-bold text-slate-100 font-mono mt-1 block truncate" title={domainAnalysis.path}>
            {domainAnalysis.path || '/'}
          </span>
        </div>
      </div>

      {/* Query Parameters */}
      <div className="mt-4 p-3.5 rounded-xl bg-slate-900/40 border border-slate-800/80">
        <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
          Query Parameters ({domainAnalysis.query_parameters?.length || 0})
        </span>
        {domainAnalysis.query_parameters && domainAnalysis.query_parameters.length > 0 ? (
          <div className="flex flex-wrap gap-1.5 mt-2">
            {domainAnalysis.query_parameters.map((param, i) => (
              <span key={i} className="text-xs font-mono bg-slate-800 text-cyan-300 px-2 py-0.5 rounded border border-slate-700">
                ?{param}=
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs font-mono text-slate-500 mt-1 block">
            No query parameters detected in URL.
          </span>
        )}
      </div>

      {/* Structural Threat Detection Badges */}
      <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap gap-2 text-xs font-mono">
        <div className={`px-2.5 py-1 rounded border flex items-center gap-1.5 ${domainAnalysis.is_ip_based ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-slate-800/60 text-slate-400 border-slate-700'}`}>
          {domainAnalysis.is_ip_based ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
          IP-Based Host: {domainAnalysis.is_ip_based ? 'YES' : 'NO'}
        </div>

        <div className={`px-2.5 py-1 rounded border flex items-center gap-1.5 ${domainAnalysis.is_shortener ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-slate-800/60 text-slate-400 border-slate-700'}`}>
          {domainAnalysis.is_shortener ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
          URL Shortener: {domainAnalysis.is_shortener ? 'YES' : 'NO'}
        </div>

        <div className={`px-2.5 py-1 rounded border flex items-center gap-1.5 ${domainAnalysis.is_punycode ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-slate-800/60 text-slate-400 border-slate-700'}`}>
          {domainAnalysis.is_punycode ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
          Punycode (xn--): {domainAnalysis.is_punycode ? 'YES' : 'NO'}
        </div>
      </div>
    </div>
  );
};
