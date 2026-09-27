import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { Dashboard } from './pages/Dashboard';
import { AnalyzerPage } from './pages/AnalyzerPage';
import { HistoryPage } from './pages/HistoryPage';
import { RulesPage } from './pages/RulesPage';
import { AboutPage } from './pages/AboutPage';
import { getHealth } from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [backendConnected, setBackendConnected] = useState<boolean>(true);

  // Poll backend health status periodically
  useEffect(() => {
    const checkConnection = async () => {
      try {
        await getHealth();
        setBackendConnected(true);
      } catch {
        setBackendConnected(false);
      }
    };

    checkConnection();
    const interval = setInterval(checkConnection, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-slate-950">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isBackendConnected={backendConnected}
      />

      {/* Main View Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <Dashboard
            onNavigateToHistory={() => setActiveTab('history')}
            onNavigateToRules={() => setActiveTab('rules')}
          />
        )}
        {activeTab === 'analyzer' && <AnalyzerPage />}
        {activeTab === 'history' && <HistoryPage />}
        {activeTab === 'rules' && <RulesPage />}
        {activeTab === 'about' && <AboutPage />}
      </main>

      {/* Persistent Footer */}
      <Footer />
    </div>
  );
}

export default App;
