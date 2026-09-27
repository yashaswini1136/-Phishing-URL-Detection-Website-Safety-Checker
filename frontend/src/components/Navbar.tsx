import React from 'react';
import { ShieldCheck, GitBranch } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isBackendConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, isBackendConnected }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'analyzer', label: 'URL Analyzer' },
    { id: 'history', label: 'Scan History' },
    { id: 'rules', label: 'Detection Rules' },
    { id: 'about', label: 'About & Docs' },
  ];

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-950/80 border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div 
            className="flex items-center space-x-3 cursor-pointer group"
            onClick={() => setActiveTab('dashboard')}
          >
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors shadow-sm shadow-cyan-500/20">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <span className="text-sm font-semibold tracking-wider text-cyan-400 uppercase font-mono block">
                Cybersecurity Engine
              </span>
              <span className="text-base font-bold text-slate-100 tracking-tight flex items-center gap-1.5">
                Phishing URL Detection & Safety Checker
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all ${
                  activeTab === item.id
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>

          {/* Backend Status indicator & GitHub Repo */}
          <div className="flex items-center space-x-3">
            <div 
              className={`flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-mono border ${
                isBackendConnected
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
              }`}
              title={isBackendConnected ? 'Backend API connected' : 'Connecting to API...'}
            >
              <span className={`w-2 h-2 rounded-full ${isBackendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span className="hidden sm:inline">
                {isBackendConnected ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}
              </span>
            </div>

            <a
              href="https://github.com/yashaswini1136/-Phishing-URL-Detection-Website-Safety-Checker.git"
              target="_blank"
              rel="noopener noreferrer"
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors flex items-center gap-1.5 text-xs font-mono"
              title="GitHub Repository"
            >
              <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">GitHub</span>
            </a>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="md:hidden flex items-center space-x-1 pb-3 overflow-x-auto">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`px-3 py-1 text-xs font-medium rounded-md whitespace-nowrap ${
                activeTab === item.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
};
