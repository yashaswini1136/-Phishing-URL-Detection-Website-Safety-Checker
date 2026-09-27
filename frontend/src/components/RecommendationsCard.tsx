import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, Info, CheckCircle2 } from 'lucide-react';
import { ClassificationType } from '../types';

interface RecommendationsCardProps {
  recommendations: string[];
  classification: ClassificationType;
  disclaimer: string;
}

export const RecommendationsCard: React.FC<RecommendationsCardProps> = ({
  recommendations,
  classification,
  disclaimer,
}) => {
  // Filter out the disclaimer from the general recommendations list so we can render it in its own distinct callout
  const actionItems = recommendations.filter(
    (rec) => !rec.includes('Pattern-based detection cannot guarantee')
  );

  const bannerKey = (classification === 'POTENTIAL_PHISHING' ? 'PHISHING' : classification) as 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

  const bannerConfig = {
    SAFE: {
      border: 'border-emerald-500/30',
      bg: 'bg-emerald-950/20',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
      title: 'Safety Evaluation Guidance',
      tag: 'LOW RISK GUIDELINES',
    },
    SUSPICIOUS: {
      border: 'border-amber-500/30',
      bg: 'bg-amber-950/20',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
      title: 'Cautionary Advisory',
      tag: 'SUSPICIOUS ADVISORY',
    },
    PHISHING: {
      border: 'border-rose-500/40',
      bg: 'bg-rose-950/25',
      icon: ShieldAlert,
      iconColor: 'text-rose-400',
      title: 'Critical Threat Warning',
      tag: 'PHISHING DEFENSE ADVISORY',
    },
  }[bannerKey];

  const BannerIcon = bannerConfig.icon;

  return (
    <div className={`glass-card rounded-2xl p-6 border ${bannerConfig.border} space-y-5`}>
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <BannerIcon className={`w-5 h-5 ${bannerConfig.iconColor}`} />
          <h3 className="text-lg font-bold text-slate-100">
            {bannerConfig.title}
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-bold uppercase">
          {bannerConfig.tag}
        </span>
      </div>

      {/* Action items list */}
      <div className="space-y-2.5">
        {actionItems.map((rec, index) => (
          <div
            key={index}
            className="flex items-start gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800/70"
          >
            <div className="mt-0.5 shrink-0">
              <CheckCircle2 className={`w-4 h-4 ${bannerConfig.iconColor}`} />
            </div>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-sans">
              {rec}
            </p>
          </div>
        ))}
      </div>

      {/* Mandatory Cybersecurity Disclaimer Callout */}
      <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/30 flex items-start gap-3">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider font-mono">
            Mandatory Cybersecurity Disclaimer
          </h4>
          <p className="text-xs text-amber-200/90 mt-1 leading-relaxed">
            {disclaimer}
          </p>
        </div>
      </div>
    </div>
  );
};
