import React, { useState, useEffect } from 'react';
import { EasmScanResult } from './types';
import { Header } from './components/Header';
import { DomainScannerBar } from './components/DomainScannerBar';
import { UnifiedScanReport } from './components/UnifiedScanReport';
import { AboutTab } from './components/AboutTab';
import { SqlDatabaseTab } from './components/SqlDatabaseTab';
import { AnalystPlaybookModal } from './components/AnalystPlaybookModal';
import { sqliteManager } from './lib/sqliteDatabase';
import { Shield, AlertTriangle, RefreshCw, Terminal } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [currentDomain, setCurrentDomain] = useState<string>('cloudflare.com');
  const [scanResult, setScanResult] = useState<EasmScanResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isPlaybookOpen, setIsPlaybookOpen] = useState<boolean>(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('surfacetrace-theme');
      if (saved === 'dark' || saved === 'light') return saved;
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return 'light';
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('surfacetrace-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
  };

  const runScan = async (domainToScan: string) => {
    const cleanDomain = domainToScan.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!cleanDomain) return;

    setCurrentDomain(cleanDomain);
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/scan?domain=${encodeURIComponent(cleanDomain)}`);
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server returned HTTP ${response.status}`);
      }

      const data: EasmScanResult = await response.json();
      setScanResult(data);

      // Asynchronously store scan results and network logs into browser-side SQLite
      sqliteManager.saveScanResult(data).catch((err) => {
        console.warn('SQLite auto-save warning:', err);
      });
    } catch (err: any) {
      console.error('Scan execution failed:', err);
      setError(err.message || 'Failed to complete attack surface scan');
    } finally {
      setIsLoading(false);
    }
  };

  // Initial scan on load
  useEffect(() => {
    runScan('cloudflare.com');
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors selection:bg-blue-600 selection:text-white">
      {/* Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenPlaybook={() => setIsPlaybookOpen(true)}
        findingsCount={scanResult?.findings.length || 0}
        theme={theme}
        onToggleTheme={toggleTheme}
      />

      {/* Domain Scanner Search & Benchmark Controls */}
      <DomainScannerBar
        onScan={runScan}
        isLoading={isLoading}
        currentDomain={currentDomain}
      />

      {/* Main Content Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Error Notice */}
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 text-xs font-mono flex items-center justify-between shadow-xs">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => runScan(currentDomain)}
              className="px-2.5 py-1 rounded bg-red-600 hover:bg-red-700 text-white font-semibold flex items-center gap-1 cursor-pointer transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry</span>
            </button>
          </div>
        )}

        {/* Tab Views */}
        {activeTab === 'about' ? (
          <AboutTab 
            onNavigateTab={(tab) => setActiveTab(tab)} 
            currentDomain={currentDomain}
            onScanDomain={(domain) => {
              runScan(domain);
              setActiveTab('overview');
            }}
          />
        ) : activeTab === 'sqlite' ? (
          <SqlDatabaseTab
            currentScan={scanResult}
            onLoadHistoricalScan={(domain) => {
              runScan(domain);
              setActiveTab('overview');
            }}
          />
        ) : scanResult ? (
          <UnifiedScanReport
            scan={scanResult}
            onNavigateTab={(tab) => setActiveTab(tab)}
          />
        ) : isLoading ? (
          <div className="py-24 text-center space-y-4">
            <div className="inline-flex p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-blue-600 dark:text-blue-400 shadow-sm">
              <Shield className="w-8 h-8 animate-pulse text-blue-600 dark:text-blue-400" />
            </div>
            <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
              Enumerating External Digital Footprint for {currentDomain}...
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto leading-relaxed">
              Connecting to public Certificate Transparency mirrors, querying DoH nameservers, inspecting SSL transport, and cross-referencing WHOIS records.
            </p>
          </div>
        ) : null}
      </main>

      {/* Analyst Playbook Modal */}
      <AnalystPlaybookModal
        isOpen={isPlaybookOpen}
        onClose={() => setIsPlaybookOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 py-6 text-xs text-slate-500 dark:text-slate-400 font-sans transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-slate-800 dark:text-slate-200">SurfaceTrace EASM</span>
            <span>•</span>
            <span>External Attack Surface Management & Threat Intelligence</span>
          </div>

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px]">
            <button
              onClick={() => setActiveTab('sqlite')}
              className="text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer font-semibold flex items-center gap-1"
            >
              <span>SQLite Audit Vault</span>
            </button>
            <span>•</span>
            <button
              onClick={() => setActiveTab('about')}
              className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer font-medium"
            >
              About & Architecture
            </button>
            <span>•</span>
            <button
              onClick={() => setIsPlaybookOpen(true)}
              className="hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
            >
              Analyst Playbook
            </button>
            <span>•</span>
            <span>MITRE ATT&CK® v14 Mapped</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
