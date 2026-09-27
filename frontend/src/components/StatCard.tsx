import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'slate';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'cyan',
}) => {
  const variantStyles = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      valueColor: 'text-cyan-400',
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      valueColor: 'text-emerald-400',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      valueColor: 'text-amber-400',
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/40',
      iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      valueColor: 'text-rose-400',
    },
    slate: {
      border: 'border-slate-700/60 hover:border-slate-600',
      iconBg: 'bg-slate-800 text-slate-300 border-slate-700',
      valueColor: 'text-slate-100',
    },
  }[variant];

  return (
    <div
      className={`glass-card glass-card-hover rounded-xl p-5 border ${variantStyles.border} transition-all duration-200`}
    >
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs uppercase font-mono font-medium tracking-wider text-slate-400 block">
            {title}
          </span>
          <div className={`text-3xl font-extrabold font-mono tracking-tight mt-1.5 ${variantStyles.valueColor}`}>
            {value}
          </div>
          {subtitle && (
            <p className="text-xs text-slate-500 mt-1 font-mono">{subtitle}</p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg border ${variantStyles.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
