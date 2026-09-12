import React, { useState } from 'react';
import { Search, Globe, ArrowRight, Loader2, Zap } from 'lucide-react';

interface DomainScannerBarProps {
  onScan: (domain: string) => void;
  isLoading: boolean;
  currentDomain: string;
}

const PRESET_DOMAINS = [
  { name: 'Cloudflare', domain: 'cloudflare.com' },
  { name: 'GitHub', domain: 'github.com' },
  { name: 'Tesla', domain: 'tesla.com' },
  { name: 'NASA', domain: 'nasa.gov' },
  { name: 'Netflix', domain: 'netflix.com' }
];

const SCAN_STEPS = [
  'Querying DNS-over-HTTPS (A, AAAA, MX, TXT, DMARC, CAA)...',
  'Harvesting Certificate Transparency logs (crt.sh)...',
  'Analyzing HTTP Security Headers & TLS transport posture...',
  'Querying WHOIS, RDAP registration & ASN network footprint...',
  'Synthesizing risk posture and mapping to MITRE ATT&CK chain...'
];

export const DomainScannerBar: React.FC<DomainScannerBarProps> = ({
  onScan,
  isLoading,
  currentDomain
}) => {
  const [inputVal, setInputVal] = useState(currentDomain || 'cloudflare.com');
  const [stepIndex, setStepIndex] = useState(0);

  // Rotate loading step description
  React.useEffect(() => {
    if (!isLoading) return;
    const interval = setInterval(() => {
      setStepIndex((prev) => (prev + 1) % SCAN_STEPS.length);
    }, 1100);
    return () => clearInterval(interval);
  }, [isLoading]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputVal.trim()) return;
    onScan(inputVal.trim());
  };

  const handleSelectPreset = (domain: string) => {
    setInputVal(domain);
    onScan(domain);
  };

  return (
    <div className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-4 py-4 sm:px-6 lg:px-8 transition-colors shadow-xs">
      <div className="max-w-7xl mx-auto">
        <form onSubmit={handleSubmit} className="relative">
          <div className="flex flex-col md:flex-row gap-3 items-stretch">
            {/* Input Bar */}
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 dark:text-slate-500">
                <Globe className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="Enter organization target domain (e.g. company.com or tesla.com)..."
                disabled={isLoading}
                className="w-full pl-11 pr-14 py-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-slate-100 placeholder-slate-400 text-sm font-mono focus:outline-none focus:bg-white dark:focus:bg-slate-950 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600 transition-all disabled:opacity-50"
              />
              {inputVal && !isLoading && (
                <button
                  type="button"
                  onClick={() => setInputVal('')}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                >
                  Clear
                </button>
              )}
            </div>

            {/* Launch Button */}
            <button
              type="submit"
              disabled={isLoading || !inputVal.trim()}
              className="inline-flex items-center justify-center space-x-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer shadow-sm"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>Mapping Surface...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-white stroke-[2.2]" />
                  <span>Map Attack Surface</span>
                  <ArrowRight className="w-4 h-4 text-white" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Loading Progress Feedback */}
        {isLoading && (
          <div className="mt-3 flex items-center space-x-2.5 bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/60 rounded-lg p-2.5 text-xs text-blue-900 dark:text-blue-300 font-mono">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-600 dark:text-blue-400 shrink-0" />
            <span className="font-semibold text-blue-700 dark:text-blue-400">Phase {stepIndex + 1}/5:</span>
            <span className="truncate">{SCAN_STEPS[stepIndex]}</span>
          </div>
        )}

        {/* Quick Presets */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 dark:text-slate-400 font-medium flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            Benchmark Targets:
          </span>
          {PRESET_DOMAINS.map((preset) => (
            <button
              key={preset.domain}
              onClick={() => handleSelectPreset(preset.domain)}
              disabled={isLoading}
              className={`px-2.5 py-1 rounded-md border text-xs font-mono transition-all cursor-pointer ${
                inputVal.toLowerCase() === preset.domain
                  ? 'bg-blue-50 text-blue-700 border-blue-300 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-700 font-semibold'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700'
              }`}
            >
              {preset.name} <span className="opacity-60 text-[10px]">({preset.domain})</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
