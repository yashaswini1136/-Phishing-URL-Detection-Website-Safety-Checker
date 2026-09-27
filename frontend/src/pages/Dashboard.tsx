import React, { useState, useEffect } from 'react';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Activity, ArrowRight, Sparkles, CheckCircle, RefreshCw } from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { AnalysisResultView } from '../components/AnalysisResultView';
import { AnalysisResult, Statistics, ScanHistoryItem } from '../types';
import { analyzeUrl, getStatistics, getHistory } from '../services/api';

interface DashboardProps {
  onNavigateToHistory: () => void;
  onNavigateToRules: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigateToHistory, onNavigateToRules }) => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [stats, setStats] = useState<Statistics>({
    total_scans: 0,
    safe_count: 0,
    suspicious_count: 0,
    phishing_count: 0,
    detection_rate: 0,
    avg_risk_score: 0,
    top_indicators: [],
  });
  const [recentScans, setRecentScans] = useState<ScanHistoryItem[]>([]);

  const fetchStatsAndHistory = async () => {
    try {
      const [statsData, historyData] = await Promise.all([
        getStatistics(),
        getHistory(undefined, undefined, 5, 0),
      ]);
      setStats(statsData);
      setRecentScans(historyData.items);
    } catch (err) {
      console.error('Error fetching dashboard statistics:', err);
    }
  };

  useEffect(() => {
    fetchStatsAndHistory();
  }, []);

  const handleAnalyze = async (urlToAnalyze?: string) => {
    const targetUrl = (urlToAnalyze || urlInput).trim();
    if (!targetUrl) {
      setError('Please enter a URL to analyze');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await analyzeUrl(targetUrl);
      setCurrentResult(result);
      setUrlInput(result.url);
      // Refresh stats and history in background
      fetchStatsAndHistory();
    } catch (err: any) {
      setError(err.message || 'Failed to analyze URL. Please check input formatting.');
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (exampleUrl: string) => {
    setUrlInput(exampleUrl);
    handleAnalyze(exampleUrl);
  };

  return (
    <div className="space-y-12">
      {/* Hero Section */}
      <section className="relative text-center pt-8 pb-4 max-w-4xl mx-auto space-y-6">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Pattern-Based Threat Intelligence &bull; Heuristic + Machine Learning</span>
        </div>

        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-slate-100">
          Analyze Before <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-emerald-400">You Trust</span>
        </h1>

        <p className="text-slate-400 text-base sm:text-lg max-w-2xl mx-auto leading-relaxed">
          Detect suspicious URL patterns and identify potential phishing threats using multi-layered heuristic feature extraction and risk scoring.
        </p>

        {/* Big Search Input Box */}
        <div className="pt-2 max-w-3xl mx-auto">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAnalyze();
            }}
            className="relative flex flex-col sm:flex-row items-stretch gap-2.5 p-2 rounded-2xl glass-card border border-cyan-500/30 shadow-2xl focus-within:border-cyan-400 focus-within:ring-2 focus-within:ring-cyan-500/20 transition-all"
          >
            <div className="relative flex-1 flex items-center">
              <Search className="w-5 h-5 text-slate-400 absolute left-4 pointer-events-none" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => {
                  setUrlInput(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="https://example.com"
                className="w-full pl-12 pr-4 py-3.5 bg-transparent text-slate-100 placeholder-slate-500 text-sm sm:text-base font-mono focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-7 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-lg shadow-cyan-500/25 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  Analyzing...
                </>
              ) : (
                <>
                  Analyze URL
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Example Buttons */}
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs font-mono">
            <span className="text-slate-500">Quick Examples:</span>
            <button
              onClick={() => handleExampleClick('https://github.com/explore')}
              className="px-3 py-1 rounded-md bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-700/80 transition-colors"
            >
              Analyze Example
            </button>
            <button
              onClick={() => handleExampleClick('https://google.com')}
              className="px-3 py-1 rounded-md bg-emerald-950/40 hover:bg-emerald-900/50 text-emerald-300 border border-emerald-500/30 transition-colors"
            >
              Safe Example
            </button>
            <button
              onClick={() => handleExampleClick('http://192.168.1.100/login/bank-verify.html')}
              className="px-3 py-1 rounded-md bg-amber-950/40 hover:bg-amber-900/50 text-amber-300 border border-amber-500/30 transition-colors"
            >
              Suspicious Example
            </button>
            <button
              onClick={() => handleExampleClick('http://paypal.com@account-verify.xyz/update')}
              className="px-3 py-1 rounded-md bg-rose-950/40 hover:bg-rose-900/50 text-rose-300 border border-rose-500/30 transition-colors"
            >
              Phishing Example
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mt-4 p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs sm:text-sm font-mono flex items-center justify-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </section>

      {/* Main Analysis Result (Displays when result exists) */}
      {currentResult && (
        <section id="analysis-result" className="pt-2">
          <AnalysisResultView
            result={currentResult}
            onReset={() => {
              setCurrentResult(null);
              setUrlInput('');
            }}
          />
        </section>
      )}

      {/* Statistics Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              Platform Telemetry & Statistics
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Aggregated historical scans and heuristic detection rates across the local database.
            </p>
          </div>

          <button
            onClick={fetchStatsAndHistory}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh statistics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard
            title="URLs Scanned"
            value={stats.total_scans}
            subtitle="Total analyzed links"
            icon={Activity}
            variant="slate"
          />
          <StatCard
            title="Safe URLs"
            value={stats.safe_count}
            subtitle="Score 0 - 29"
            icon={ShieldCheck}
            variant="emerald"
          />
          <StatCard
            title="Suspicious URLs"
            value={stats.suspicious_count}
            subtitle="Score 30 - 59"
            icon={AlertTriangle}
            variant="amber"
          />
          <StatCard
            title="Phishing URLs"
            value={stats.phishing_count}
            subtitle="Score 60 - 100"
            icon={ShieldAlert}
            variant="rose"
          />
          <StatCard
            title="Detection Rate"
            value={`${stats.detection_rate}%`}
            subtitle="Threat ratio"
            icon={Sparkles}
            variant="cyan"
          />
        </div>
      </section>

      {/* Recent Scans Table */}
      <section className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
          <div>
            <h3 className="text-lg font-bold text-slate-100">
              Recent Threat Scans
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Latest security evaluations performed on this station.
            </p>
          </div>

          <button
            onClick={onNavigateToHistory}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            View All Scans <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="mt-4 overflow-x-auto">
          {recentScans.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-slate-500">
              No scan history records available yet. Enter a URL above to run your first evaluation.
            </div>
          ) : (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                  <th className="pb-3">URL</th>
                  <th className="pb-3">Score</th>
                  <th className="pb-3">Classification</th>
                  <th className="pb-3">Indicators</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 font-medium text-slate-200 truncate max-w-xs sm:max-w-md">
                      {scan.url}
                    </td>
                    <td className="py-3">
                      <span className="font-bold text-slate-300">
                        {scan.risk_score}/100
                      </span>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                          scan.classification === 'SAFE'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : scan.classification === 'SUSPICIOUS'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {scan.classification}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400">
                      {scan.indicator_count} flagged
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => {
                          setUrlInput(scan.url);
                          handleAnalyze(scan.url);
                          window.scrollTo({ top: 0, behavior: 'smooth' });
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
};
