import React, { useState, useEffect } from 'react';
import { History, Search, Trash2, Eye, RefreshCw, AlertTriangle, ShieldCheck, ShieldAlert, X } from 'lucide-react';
import { ScanHistoryItem, AnalysisResult, ClassificationType } from '../types';
import { getHistory, getScanById, deleteScan, clearAllScans } from '../services/api';
import { AnalysisResultView } from '../components/AnalysisResultView';

export const HistoryPage: React.FC = () => {
  const [historyItems, setHistoryItems] = useState<ScanHistoryItem[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [search, setSearch] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('ALL');
  const [loading, setLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState<AnalysisResult | null>(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await getHistory(search || undefined, classificationFilter, 100, 0);
      setHistoryItems(data.items);
      setTotalCount(data.total);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [classificationFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleViewDetail = async (id: number) => {
    setModalLoading(true);
    try {
      const detail = await getScanById(id);
      setSelectedScan(detail);
    } catch (err) {
      console.error('Failed to load scan detail:', err);
    } finally {
      setModalLoading(false);
    }
  };

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await deleteScan(id);
      setHistoryItems((prev) => prev.filter((item) => item.id !== id));
      setTotalCount((prev) => Math.max(0, prev - 1));
      if (selectedScan && selectedScan.id === id) {
        setSelectedScan(null);
      }
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  const handleClearAll = async () => {
    try {
      await clearAllScans();
      setHistoryItems([]);
      setTotalCount(0);
      setSelectedScan(null);
      setConfirmClear(false);
    } catch (err) {
      console.error('Failed to clear scans:', err);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-100 flex items-center gap-3">
            <History className="w-8 h-8 text-cyan-400" />
            Security Scan History
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Audit logs of evaluated URLs stored in SQLite local database.
          </p>
        </div>

        {historyItems.length > 0 && (
          <div>
            {confirmClear ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleClearAll}
                  className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold text-xs font-mono transition-colors"
                >
                  Confirm Delete All
                </button>
                <button
                  onClick={() => setConfirmClear(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs font-mono hover:bg-slate-700 transition-colors"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmClear(true)}
                className="px-3.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" /> Clear History
              </button>
            )}
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-card rounded-2xl p-4 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Classification Filter Tabs */}
        <div className="flex items-center space-x-1 w-full md:w-auto overflow-x-auto">
          {['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'].map((type) => (
            <button
              key={type}
              onClick={() => setClassificationFilter(type)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium whitespace-nowrap transition-colors ${
                classificationFilter === type
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Search input */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80 flex items-center">
          <Search className="w-4 h-4 text-slate-500 absolute left-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by URL domain..."
            className="w-full pl-9 pr-8 py-1.5 bg-slate-900 text-xs font-mono text-slate-100 placeholder-slate-500 rounded-lg border border-slate-700 focus:outline-none focus:border-cyan-400"
          />
          {search && (
            <button
              type="button"
              onClick={() => {
                setSearch('');
                getHistory(undefined, classificationFilter).then((d) => {
                  setHistoryItems(d.items);
                  setTotalCount(d.total);
                });
              }}
              className="absolute right-2.5 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </form>
      </div>

      {/* Scans Table */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <span className="text-xs font-mono text-slate-400">
            Displaying {historyItems.length} of {totalCount} records
          </span>
          <button
            onClick={fetchHistory}
            className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1 font-mono"
            title="Refresh Table"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>

        <div className="mt-4 overflow-x-auto">
          {historyItems.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-slate-500">
              {loading ? 'Loading records...' : 'No scan history matching your search criteria.'}
            </div>
          ) : (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                  <th className="pb-3 w-16">ID</th>
                  <th className="pb-3">URL</th>
                  <th className="pb-3">Score</th>
                  <th className="pb-3">Classification</th>
                  <th className="pb-3">Indicators</th>
                  <th className="pb-3">Timestamp</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {historyItems.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => handleViewDetail(item.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 text-slate-500 font-bold">
                      #{item.id}
                    </td>
                    <td className="py-3 font-medium text-slate-200 truncate max-w-xs md:max-w-md group-hover:text-cyan-300">
                      {item.url}
                    </td>
                    <td className="py-3 font-bold text-slate-300">
                      {item.risk_score}/100
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                          item.classification === 'SAFE'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : item.classification === 'SUSPICIOUS'
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                        }`}
                      >
                        {item.classification}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400">
                      {item.indicator_count}
                    </td>
                    <td className="py-3 text-slate-400 whitespace-nowrap">
                      {new Date(item.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleViewDetail(item.id)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title="View detailed report"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={(e) => handleDelete(item.id, e)}
                          className="p-1 rounded bg-slate-800 hover:bg-rose-950/80 text-rose-400 transition-colors"
                          title="Delete entry"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Modal Popup for Detailed Scan Report */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-5xl max-h-[90vh] overflow-y-auto rounded-3xl glass-card border border-cyan-500/30 p-6 sm:p-8 bg-slate-950 shadow-2xl">
            <div className="flex items-center justify-between pb-4 mb-6 border-b border-slate-800">
              <span className="text-sm font-mono text-cyan-400 font-bold">
                HISTORICAL EVALUATION REPORT &bull; SCAN #{selectedScan.id}
              </span>
              <button
                onClick={() => setSelectedScan(null)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <AnalysisResultView result={selectedScan} />
          </div>
        </div>
      )}
    </div>
  );
};
