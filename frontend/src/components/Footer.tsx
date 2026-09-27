import React from 'react';
import { Shield, AlertTriangle } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="mt-20 border-t border-slate-800/80 bg-slate-950/60 backdrop-blur-sm py-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center space-x-3 text-slate-400 text-sm">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span>
              Phishing URL Detection & Website Safety Checker &bull; Educational Platform
            </span>
          </div>

          <div className="flex items-center space-x-6 text-xs text-slate-500 font-mono">
            <span>FastAPI Backend</span>
            <span>React + TypeScript</span>
            <span>Rule Engine + ML</span>
            <a
              href="https://github.com/yashaswini1136/-Phishing-URL-Detection-Website-Safety-Checker.git"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              GitHub Repository
            </a>
          </div>
        </div>

        <div className="mt-6 pt-6 border-t border-slate-900 flex items-start space-x-3 text-xs text-slate-500">
          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <p>
            <strong>Important Educational Disclaimer:</strong> Pattern-based detection cannot guarantee that a website is safe or malicious. A URL classified as Safe may still be compromised or host malicious content. This system performs local heuristic and machine learning pattern evaluation without conducting server-side HTTP requests, mitigating Server-Side Request Forgery (SSRF) vulnerabilities. Always verify links and sources independently.
          </p>
        </div>
      </div>
    </footer>
  );
};
