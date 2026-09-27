import React, { useState, useEffect } from 'react';
import { Sliders, Shield, AlertTriangle, Info, CheckCircle2, Terminal } from 'lucide-react';
import { DetectionRule, SeverityType } from '../types';
import { getRules } from '../services/api';

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  useEffect(() => {
    getRules()
      .then((data) => {
        setRules(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load rules:', err);
        setLoading(false);
      });
  }, []);

  const getSeverityBadge = (sev: SeverityType) => {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
      default:
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    }
  };

  const filteredRules = severityFilter === 'ALL'
    ? rules
    : rules.filter((r) => r.severity === severityFilter);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-slate-100 flex items-center gap-3">
          <Sliders className="w-8 h-8 text-cyan-400" />
          Active Detection Rules & Heuristics
        </h1>
        <p className="text-slate-400 text-sm mt-1 max-w-3xl">
          Overview of deterministic pattern analysis rules, severity classifications, and risk score weights configured in the backend engine.
        </p>
      </div>

      {/* Threshold Explanation Banner */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-cyan-400 flex items-center gap-2">
          <Info className="w-4 h-4" /> Scoring Engine Thresholds
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          When a target URL is submitted, all active rules are evaluated independently. Triggered rule weights are summed to compute a normalized risk score from 0 to 100.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-4">
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30">
            <span className="text-xs font-mono font-bold text-emerald-400 block">
              SAFE VERDICT
            </span>
            <span className="text-2xl font-black font-mono text-emerald-300 mt-1 block">
              0 &ndash; 29
            </span>
            <p className="text-[11px] text-slate-400 mt-1">
              Low heuristic footprint. No severe phishing indicators or obfuscation observed.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30">
            <span className="text-xs font-mono font-bold text-amber-400 block">
              SUSPICIOUS VERDICT
            </span>
            <span className="text-2xl font-black font-mono text-amber-300 mt-1 block">
              30 &ndash; 59
            </span>
            <p className="text-[11px] text-slate-400 mt-1">
              Moderate threat level. Multiple anomalous patterns or single high-weight indicator.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-rose-950/25 border border-rose-500/30">
            <span className="text-xs font-mono font-bold text-rose-400 block">
              PHISHING VERDICT
            </span>
            <span className="text-2xl font-black font-mono text-rose-300 mt-1 block">
              60 &ndash; 100
            </span>
            <p className="text-[11px] text-slate-400 mt-1">
              Critical indicators present (e.g. IP host, @ redirect, Punycode, high-risk TLDs).
            </p>
          </div>
        </div>
      </div>

      {/* Rules Table Section */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h3 className="text-lg font-bold text-slate-100">
              Active Heuristic Engine Rules ({filteredRules.length})
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Rules currently evaluated on each incoming URL.
            </p>
          </div>

          {/* Severity filter */}
          <div className="flex items-center space-x-1">
            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 text-xs font-mono rounded-lg transition-colors ${
                  severityFilter === sev
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          {loading ? (
            <div className="py-12 text-center text-xs font-mono text-slate-500">
              Loading detection rules...
            </div>
          ) : (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                  <th className="pb-3">Rule Name</th>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Weight</th>
                  <th className="pb-3">Rule Description & Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredRules.map((rule) => (
                  <tr key={rule.rule_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 font-bold text-slate-200 whitespace-nowrap">
                      {rule.name}
                    </td>
                    <td className="py-3.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getSeverityBadge(rule.severity)}`}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="py-3.5 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold border border-slate-700">
                        +{rule.weight}
                      </span>
                    </td>
                    <td className="py-3.5 text-slate-400 font-sans text-xs leading-relaxed max-w-xl">
                      {rule.description}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Developer / Admin Configuration Notice */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center gap-2 text-cyan-400">
          <Terminal className="w-5 h-5" />
          <h4 className="text-sm font-bold uppercase font-mono">
            Rule Customization & Configuration Architecture
          </h4>
        </div>
        <p className="text-xs text-slate-400 mt-2 leading-relaxed font-sans">
          To maintain zero-trust security and prevent unauthorized remote modification of threat sensitivity, rule weights and suspicious keyword sets are configured server-side in <code className="text-cyan-300 font-mono bg-slate-900 px-1.5 py-0.5 rounded">backend/config.py</code>. Educators and administrators can modify rule parameters, weights, and high-risk TLD lists directly without altering core detection logic.
        </p>
      </div>
    </div>
  );
};
