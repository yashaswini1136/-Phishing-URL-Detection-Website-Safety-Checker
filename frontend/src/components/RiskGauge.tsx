import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, AlertTriangle, ShieldAlert, Cpu } from 'lucide-react';
import { ClassificationType, RiskLevelType } from '../types';

interface RiskGaugeProps {
  score: number;
  classification: ClassificationType;
  riskLevel: RiskLevelType;
  detectionMethod?: string;
  mlConfidence?: string | null;
  confidence?: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  classification,
  riskLevel,
  detectionMethod = 'Rule-Based Analysis',
  mlConfidence,
  confidence,
}) => {
  const [displayScore, setDisplayScore] = useState(0);

  // Animated number counter
  useEffect(() => {
    let start = 0;
    const duration = 1000;
    const stepTime = 15;
    const steps = duration / stepTime;
    const increment = score / steps;

    const timer = setInterval(() => {
      start += increment;
      if (start >= score) {
        setDisplayScore(score);
        clearInterval(timer);
      } else {
        setDisplayScore(Math.round(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [score]);

  // Normalize key for styling
  const styleKey = (classification === 'POTENTIAL_PHISHING' ? 'PHISHING' : classification) as 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

  // Styling configurations depending on classification
  const config = {
    SAFE: {
      color: '#10b981',
      bgGlow: 'rgba(16, 185, 129, 0.15)',
      borderColor: 'border-emerald-500/40',
      textColor: 'text-emerald-400',
      badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      icon: ShieldCheck,
      headline: 'URL Appears Safe',
      subtext: 'No prominent phishing indicators detected. Static domain and profile match legitimate baseline.',
    },
    SUSPICIOUS: {
      color: '#f59e0b',
      bgGlow: 'rgba(245, 158, 11, 0.15)',
      borderColor: 'border-amber-500/40',
      textColor: 'text-amber-400',
      badgeBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      icon: AlertTriangle,
      headline: 'Suspicious URL Detected',
      subtext: 'Multiple risk factors observed. Exercise heightened caution before visiting.',
    },
    PHISHING: {
      color: '#ef4444',
      bgGlow: 'rgba(239, 68, 68, 0.2)',
      borderColor: 'border-rose-500/40',
      textColor: 'text-rose-400',
      badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      icon: ShieldAlert,
      headline: 'Potential Phishing URL Detected',
      subtext: 'High-risk characteristics identified. Do not input credentials, passwords, or payment details.',
    },
  }[styleKey];

  const IconComponent = config.icon;

  // Display label for classification badge
  const displayLabel = classification === 'POTENTIAL_PHISHING' ? 'POTENTIAL PHISHING' : classification;

  // SVG Gauge calculations
  const size = 210;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Representing 240 degrees gauge arc
  const arcFraction = 0.75;
  const strokeDashoffset = circumference * (1 - (score / 100) * arcFraction);

  return (
    <div 
      className={`glass-card rounded-2xl p-6 sm:p-8 border ${config.borderColor} relative overflow-hidden transition-all shadow-xl`}
      style={{
        background: `radial-gradient(circle at top center, ${config.bgGlow}, rgba(15, 23, 42, 0.75) 70%)`,
      }}
    >
      <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
        {/* Left: Gauge Display */}
        <div className="relative flex flex-col items-center justify-center shrink-0">
          <svg width={size} height={size} className="transform -rotate-90">
            {/* Background circle track */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              stroke="#1e293b"
              strokeWidth={strokeWidth}
              fill="transparent"
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - arcFraction)}
              strokeLinecap="round"
            />
            {/* Animated risk score stroke */}
            <motion.circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              stroke={config.color}
              strokeWidth={strokeWidth}
              fill="transparent"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset: strokeDashoffset }}
              transition={{ duration: 1.2, ease: 'easeOut' }}
              strokeLinecap="round"
            />
          </svg>

          {/* Center text in gauge */}
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <div className="flex items-baseline justify-center">
              <span className={`text-5xl font-black font-mono tracking-tight ${config.textColor}`}>
                {displayScore}
              </span>
              <span className="text-slate-500 font-mono text-lg ml-1">/100</span>
            </div>
            <span className="text-xs uppercase tracking-widest font-mono text-slate-400 mt-1 font-semibold">
              Risk Score
            </span>
          </div>
        </div>

        {/* Right: Risk Details & Verdict */}
        <div className="flex-1 text-center lg:text-left space-y-4">
          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-2.5">
            {/* Final Classification Badge */}
            <span className={`px-4 py-1.5 rounded-full text-sm font-bold font-mono tracking-wider border flex items-center gap-1.5 shadow-sm ${config.badgeBg}`}>
              <IconComponent className="w-4 h-4" />
              {displayLabel}
            </span>

            {/* Risk Level Badge */}
            <span className="px-3 py-1 rounded-full text-xs font-semibold font-mono bg-slate-800 text-slate-300 border border-slate-700">
              Risk Level: {riskLevel}
            </span>

            {/* Confidence Badge */}
            {confidence !== undefined && (
              <span className="px-3 py-1 rounded-full text-xs font-semibold font-mono bg-indigo-950/60 text-indigo-300 border border-indigo-800/50">
                Confidence: {Math.round(confidence * 100)}%
              </span>
            )}

            {/* Engine Methodology */}
            <span className="px-3 py-1 rounded-full text-xs font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 flex items-center gap-1">
              <Cpu className="w-3.5 h-3.5" />
              {detectionMethod}
              {mlConfidence && <span className="text-slate-400">({mlConfidence})</span>}
            </span>
          </div>

          <div>
            <h2 className={`text-2xl sm:text-3xl font-bold tracking-tight ${config.textColor}`}>
              {config.headline}
            </h2>
            <p className="text-slate-300 text-sm mt-1.5 leading-relaxed max-w-xl">
              {config.subtext}
            </p>
          </div>

          <div className="pt-2 flex flex-wrap items-center justify-center lg:justify-start gap-6 text-xs text-slate-400 font-mono">
            <div>
              <span className="text-slate-500 block">SCORE THRESHOLD</span>
              <span>
                {classification === 'SAFE' && '0 - 29 (Safe Zone)'}
                {classification === 'SUSPICIOUS' && '30 - 59 (Suspicious Zone)'}
                {(classification === 'PHISHING' || classification === 'POTENTIAL_PHISHING') && '60 - 100 (Phishing Zone)'}
              </span>
            </div>
            <div className="border-l border-slate-800 pl-6">
              <span className="text-slate-500 block">SEVERITY RATING</span>
              <span className="font-semibold text-slate-200">{riskLevel} RISK</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
