import React, { useState } from 'react';
import { Search, ArrowRight, RefreshCw, AlertTriangle, Shield, CheckCircle, Info } from 'lucide-react';
import { AnalysisResultView } from '../components/AnalysisResultView';
import { AnalysisResult } from '../types';
import { analyzeUrl } from '../services/api';

export const AnalyzerPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleAnalyze = async (urlOverride?: string) => {
    const target = (urlOverride || urlInput).trim();
    if (!target) {
      setError('Please provide a URL to analyze.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await analyzeUrl(target);
      setResult(res);
      setUrlInput(res.url);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Please check URL formatting.');
    } finally {
      setLoading(false);
    }
  };

  const sampleCases = [
    { label: 'Legitimate Standard', url: 'https://www.wikipedia.org/wiki/Computer_security', tag: 'Safe' },
    { label: 'IP Address Scheme', url: 'http://84.17.45.12/webscr?cmd=_login-run', tag: 'Phishing' },
    { label: 'Punycode Homoglyph', url: 'http://www.xn--googl-fsa.com/search', tag: 'Suspicious' },
    { label: '@ Credential Obfuscation', url: 'https://login.chase.com@malicious-harvest.xyz/signin', tag: 'Phishing' },
    { label: 'Subdomain Stacking', url: 'https://secure.banking.portal.login.account-update.buzz/auth', tag: 'Phishing' },
    { label: 'URL Shortener', url: 'https://bit.ly/secure-login-free-bonus-claim-now', tag: 'Suspicious' },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-slate-100 flex items-center gap-3">
          <Shield className="w-8 h-8 text-cyan-400" />
          URL Threat Analysis Console
        </h1>
        <p className="text-slate-400 text-sm mt-1 max-w-3xl">
          Deep pattern inspection of uniform resource locators. Analyzes structural syntax, domain hierarchies, character obfuscation, credential lures, and top-level domain abuse vectors.
        </p>
      </div>

      {/* Input Console */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAnalyze();
          }}
          className="space-y-4"
        >
          <label className="text-xs uppercase font-mono tracking-wider text-slate-400 font-semibold block">
            Target URL Input (HTTP, HTTPS, or Hostname)
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-5 h-5 text-slate-500 absolute left-4 top-3.5" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://secure.bank.example.com/login?token=xyz"
                className="w-full pl-12 pr-4 py-3 bg-slate-900 text-slate-100 placeholder-slate-500 text-sm font-mono rounded-xl border border-slate-700 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm font-mono tracking-wider flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  ANALYZING
                </>
              ) : (
                <>
                  EXECUTE SCAN
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Quick Preload Test Cases */}
          <div className="pt-2">
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-2 font-semibold">
              Select Preset Test Vectors:
            </span>
            <div className="flex flex-wrap gap-2">
              {sampleCases.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setUrlInput(s.url);
                    handleAnalyze(s.url);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 text-xs font-mono border border-slate-700/80 text-slate-300 flex items-center gap-2 transition-colors"
                >
                  <span>{s.label}</span>
                  <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold uppercase ${
                    s.tag === 'Safe' ? 'bg-emerald-500/10 text-emerald-400' :
                    s.tag === 'Suspicious' ? 'bg-amber-500/10 text-amber-400' :
                    'bg-rose-500/10 text-rose-400'
                  }`}>
                    {s.tag}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </form>
      </div>

      {/* Result Section */}
      {result ? (
        <AnalysisResultView
          result={result}
          onReset={() => {
            setResult(null);
            setUrlInput('');
          }}
        />
      ) : (
        <div className="py-16 text-center rounded-2xl border border-dashed border-slate-800 bg-slate-950/30">
          <Info className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-bold text-slate-300">
            Awaiting Target URL
          </h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
            Input a URL string or select one of the security preset test vectors above to generate an in-depth heuristic security evaluation report.
          </p>
        </div>
      )}
    </div>
  );
};
