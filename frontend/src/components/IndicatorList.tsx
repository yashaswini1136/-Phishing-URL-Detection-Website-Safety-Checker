import React from 'react';
import { AlertCircle, CheckCircle2, ShieldCheck, Zap } from 'lucide-react';
import { Indicator } from '../types';

interface IndicatorListProps {
  indicators: Indicator[];
  riskScore: number;
}

export const IndicatorList: React.FC<IndicatorListProps> = ({ indicators, riskScore }) => {
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
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

  return (
    <div className="glass-card rounded-2xl p-6 border border-slate-800">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
        <div>
          <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-cyan-400" />
            Explainable Threat Indicators
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Breakdown of triggered heuristic indicators that contributed to the {riskScore}/100 score.
          </p>
        </div>
        <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
          {indicators.length} {indicators.length === 1 ? 'Indicator' : 'Indicators'} Found
        </span>
      </div>

      <div className="mt-4 space-y-3">
        {indicators.length === 0 ? (
          <div className="py-8 px-4 rounded-xl bg-emerald-950/20 border border-emerald-500/20 text-center">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-emerald-300">
              No Suspicious Threat Indicators Triggered
            </p>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              This URL did not trip heuristics for IP addressing, sensitive credential keywords, Punycode spoofing, or high-risk TLDs.
            </p>
          </div>
        ) : (
          indicators.map((ind, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-300 font-mono text-xs flex items-center justify-center shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h4 className="text-sm font-semibold text-slate-100">
                        {ind.name}
                      </h4>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${getSeverityBadge(ind.severity)}`}>
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1 font-mono bg-slate-950/60 px-2.5 py-1.5 rounded border border-slate-800">
                      {ind.detail}
                    </p>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                      <strong className="text-slate-300">Why this matters:</strong> {ind.description}
                    </p>
                  </div>
                </div>

                <div className="shrink-0 text-right">
                  <span className="inline-flex items-center text-xs font-mono font-bold px-2 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                    +{ind.score}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
