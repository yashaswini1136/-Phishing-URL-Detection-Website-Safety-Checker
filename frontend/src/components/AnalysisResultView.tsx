import React, { useState } from 'react';
import { Copy, Check, RefreshCw, Cpu, Clock, Link2, ShieldCheck, ShieldAlert } from 'lucide-react';
import { AnalysisResult } from '../types';
import { RiskGauge } from './RiskGauge';
import { IndicatorList } from './IndicatorList';
import { FeatureTable } from './FeatureTable';
import { DomainAnalysisCard } from './DomainAnalysisCard';
import { RecommendationsCard } from './RecommendationsCard';

interface AnalysisResultViewProps {
  result: AnalysisResult;
  onReset?: () => void;
}

export const AnalysisResultView: React.FC<AnalysisResultViewProps> = ({ result, onReset }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formattedDate = new Date(result.timestamp).toLocaleString();

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Target URL Header Bar */}
      <div className="glass-card rounded-2xl p-5 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1 overflow-hidden">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <Link2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>ANALYZED TARGET URL:</span>
            <span className="text-slate-500">Scan #{result.id}</span>
          </div>
          <div className="font-mono text-sm sm:text-base font-bold text-slate-100 truncate max-w-3xl">
            {result.url}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
            title="Copy URL"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy URL'}
          </button>

          {onReset && (
            <button
              onClick={onReset}
              className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Scan Another
            </button>
          )}
        </div>
      </div>

      {/* URL SECURITY ASSESSMENT Executive Summary */}
      <div className="glass-card rounded-2xl p-6 border border-cyan-500/30 bg-slate-900/40 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-slate-100 tracking-wide uppercase font-mono">
              URL Security Assessment
            </h3>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700">
            Scan #{result.id} &bull; {result.processing_time_ms ? `${result.processing_time_ms}ms` : '<10ms'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[11px]">CLASSIFICATION</span>
            <span className={`text-base font-bold mt-1 block uppercase ${
              result.classification === 'SAFE'
                ? 'text-emerald-400'
                : result.classification === 'SUSPICIOUS'
                ? 'text-amber-400'
                : 'text-rose-400'
            }`}>
              {result.classification === 'POTENTIAL_PHISHING' ? 'Potential Phishing' : result.classification}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[11px]">RISK SCORE & LEVEL</span>
            <span className="text-base font-bold text-slate-100 mt-1 block">
              {result.risk_score}/100 &bull; {result.risk_level}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[11px]">CALIBRATED CONFIDENCE</span>
            <span className="text-base font-bold text-indigo-300 mt-1 block">
              {Math.round(result.confidence * 100)}%
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
            <span className="text-slate-500 block text-[11px]">DETECTION ENGINE</span>
            <span className="text-base font-bold text-cyan-300 mt-1 block truncate">
              {result.detection_method}
            </span>
          </div>
        </div>

        {/* Positive Legitimacy Evidence or Threat Indicators count */}
        <div className="flex flex-wrap items-center gap-3 pt-1 text-xs font-mono text-slate-400">
          <span className="px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700 text-slate-300">
            Indicators Triggered: <strong className="text-cyan-300">{result.indicator_count}</strong>
          </span>
          {result.legitimacy_credits !== undefined && result.legitimacy_credits < 0 && (
            <span className="px-2.5 py-1 rounded bg-emerald-950/50 border border-emerald-500/30 text-emerald-300 flex items-center gap-1.5">
              <Check className="w-3.5 h-3.5" /> Positive Legitimacy Credit: {result.legitimacy_credits} pts (Verified domain/brand profile)
            </span>
          )}
          {result.features?.has_brand_impersonation && (
            <span className="px-2.5 py-1 rounded bg-rose-950/50 border border-rose-500/30 text-rose-300 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" /> Impersonation Target: {result.features.impersonated_brand}
            </span>
          )}
        </div>
      </div>

      {/* Main Risk Gauge Visualizer */}
      <RiskGauge
        score={result.risk_score}
        classification={result.classification}
        riskLevel={result.risk_level}
        detectionMethod={result.detection_method}
        mlConfidence={result.ml_metadata?.hybrid_confidence}
        confidence={result.confidence}
      />

      {/* Grid: Domain Architecture & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <DomainAnalysisCard domainAnalysis={result.domain_analysis} />
        <RecommendationsCard
          recommendations={result.recommendations}
          classification={result.classification}
          disclaimer={result.disclaimer}
        />
      </div>

      {/* Explainable Threat Indicators */}
      <IndicatorList
        indicators={result.indicators}
        riskScore={result.risk_score}
      />

      {/* Extracted Feature Table */}
      <FeatureTable features={result.features} />

      {/* Machine Learning Architecture Card (if available) */}
      {result.ml_metadata && result.ml_metadata.ml_available && (
        <div className="glass-card rounded-2xl p-6 border border-cyan-500/30 bg-cyan-950/10">
          <div className="flex items-center justify-between pb-3 border-b border-cyan-900/40">
            <div className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <h4 className="text-base font-bold text-cyan-200">
                Machine Learning Model Evaluation
              </h4>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold">
              {result.ml_metadata.model_type || 'Random Forest Classifier'}
            </span>
          </div>

          <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 block text-[11px]">ML PHISHING PROBABILITY</span>
              <span className="text-lg font-bold text-slate-100 mt-1 block">
                {result.ml_metadata.ml_phishing_probability !== null
                  ? `${(result.ml_metadata.ml_phishing_probability * 100).toFixed(1)}%`
                  : 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 block text-[11px]">MODEL PREDICTION</span>
              <span className={`text-lg font-bold mt-1 block ${result.ml_metadata.ml_prediction === 'PHISHING' ? 'text-rose-400' : 'text-emerald-400'}`}>
                {result.ml_metadata.ml_prediction || 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400 block text-[11px]">ARCHITECTURE</span>
              <span className="text-lg font-bold text-cyan-300 mt-1 block">
                Hybrid Rule + ML
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-3 font-sans">
            The hybrid architecture combines deterministic rule-based explainability with a 42-feature scikit-learn random forest classifier to evaluate multi-dimensional pattern similarity.
          </p>
        </div>
      )}

      {/* Timestamp footer */}
      <div className="flex items-center justify-between text-xs font-mono text-slate-500 pt-2 border-t border-slate-850">
        <span className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5" /> Scan evaluated on {formattedDate}
        </span>
        <span>Secure Local Pattern Engine &bull; Zero Remote Network Calls</span>
      </div>
    </div>
  );
};
