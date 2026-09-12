import React, { useState } from 'react';
import { EasmScanResult } from '../types';
import { 
  Sparkles, ShieldAlert, ShieldCheck, ArrowRight, Loader2, 
  Terminal, RefreshCw, Layers, CheckCircle2, AlertTriangle, FileText
} from 'lucide-react';

interface AiThreatReportTabProps {
  scan: EasmScanResult;
}

interface ThreatBriefingData {
  adversaryAnalysis: string;
  mitreKillChain: {
    phase: string;
    tactic: string;
    adversaryMethod: string;
    vulnerabilityLeveraged: string;
  }[];
  topHardeningPriorities: {
    priority: number;
    action: string;
    cisControl: string;
    estimatedRiskReduction: string;
  }[];
  source?: 'gemini-live' | 'deterministic-intel';
  notice?: string;
}

export const AiThreatReportTab: React.FC<AiThreatReportTabProps> = ({ scan }) => {
  const [briefing, setBriefing] = useState<ThreatBriefingData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchBriefing = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/gemini/threat-briefing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scan),
      });

      if (!res.ok) {
        throw new Error('Failed to generate threat briefing from server');
      }

      const data = await res.json();
      setBriefing(data);
    } catch (err: any) {
      setError(err.message || 'Error generating AI threat model');
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-generate on first open if empty
  React.useEffect(() => {
    if (!briefing && !isLoading) {
      fetchBriefing();
    }
  }, [scan.domain]);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 flex items-center justify-center text-amber-600 dark:text-amber-400 shrink-0">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                Adversary Threat Simulation & MITRE ATT&CK Playbook
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Automated red-team perspective simulating how initial access brokers prioritize <span className="font-mono text-blue-600 dark:text-blue-400 font-semibold">{scan.domain}</span>
              </p>
            </div>
          </div>

          <button
            onClick={fetchBriefing}
            disabled={isLoading}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-200 dark:border-slate-700 transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-blue-600 dark:text-blue-400 ${isLoading ? 'animate-spin' : ''}`} />
            <span>{isLoading ? 'Synthesizing...' : 'Regenerate Simulation'}</span>
          </button>
        </div>

        {isLoading ? (
          <div className="py-16 text-center space-y-3">
            <Loader2 className="w-8 h-8 animate-spin text-blue-600 dark:text-blue-400 mx-auto" />
            <p className="font-semibold text-slate-800 dark:text-slate-200 text-sm">
              Running Gemini AI Red Team Threat Modeler...
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Correlating discovered subdomains, mail authentication policies, and header postures against adversary playbooks
            </p>
          </div>
        ) : error ? (
          <div className="p-4 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 text-xs text-red-700 dark:text-red-300 font-mono space-y-2">
            <div className="font-bold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400" />
              Failed to generate AI threat model
            </div>
            <p>{error}</p>
            <button
              onClick={fetchBriefing}
              className="px-3 py-1 rounded bg-red-600 hover:bg-red-700 text-white text-xs mt-2 font-sans font-medium cursor-pointer"
            >
              Retry Generation
            </button>
          </div>
        ) : briefing ? (
          <div className="space-y-6">
            {/* Notice / Engine Origin Banner */}
            {briefing.notice && (
              <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-xs text-amber-800 dark:text-amber-300 flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-semibold block">Fault-Tolerant Intelligence Active:</span>
                  <span className="text-[11px] leading-relaxed text-amber-700 dark:text-amber-400">{briefing.notice}</span>
                </div>
              </div>
            )}

            {/* 1. Adversary Analysis Narrative */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-amber-700 dark:text-amber-400 font-mono flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                  Red Team Adversarial Threat Evaluation:
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  briefing.source === 'gemini-live' 
                    ? 'bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800' 
                    : 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800'
                }`}>
                  {briefing.source === 'gemini-live' ? 'Gemini 2.5 Flash' : 'SurfaceTrace EASM Intel Engine'}
                </span>
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans whitespace-pre-line">
                {briefing.adversaryAnalysis}
              </p>
            </div>

            {/* 2. Simulated Adversary Kill Chain */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                Simulated 3-Stage Attack Vector:
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {briefing.mitreKillChain.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-50/60 dark:bg-slate-950/90 border border-slate-200 dark:border-slate-800 space-y-2 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between text-[11px] font-mono mb-1">
                        <span className="text-blue-600 dark:text-blue-400 font-bold">Step 0{idx + 1}</span>
                        <span className="text-slate-500">{step.phase}</span>
                      </div>
                      <h4 className="font-bold text-xs text-slate-900 dark:text-slate-100">{step.tactic}</h4>
                      <p className="text-xs text-slate-600 dark:text-slate-300 font-sans mt-2 leading-relaxed">
                        {step.adversaryMethod}
                      </p>
                    </div>

                    <div className="pt-2 mt-2 border-t border-slate-200 dark:border-slate-900 text-[11px] font-mono">
                      <span className="text-red-600 dark:text-red-400 block text-[10px] uppercase font-bold font-sans">Exploited Surface:</span>
                      <span className="text-slate-600 dark:text-slate-400">{step.vulnerabilityLeveraged}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 3. CIS Controls & Top Hardening Priorities */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                Top 3 Defensive Engineering Priorities (Mapped to CIS Controls v8):
              </h3>

              <div className="space-y-2.5">
                {briefing.topHardeningPriorities.map((item) => (
                  <div
                    key={item.priority}
                    className="p-3.5 rounded-xl bg-slate-50/60 dark:bg-slate-950/90 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-6 h-6 rounded-full bg-emerald-100 dark:bg-emerald-950 border border-emerald-300 dark:border-emerald-800 flex items-center justify-center font-mono font-bold text-emerald-700 dark:text-emerald-400 text-xs shrink-0">
                        {item.priority}
                      </div>
                      <div>
                        <div className="font-bold text-slate-900 dark:text-slate-100">{item.action}</div>
                        <div className="text-[11px] font-mono text-blue-600 dark:text-blue-400 mt-0.5">
                          {item.cisControl}
                        </div>
                      </div>
                    </div>

                    <div className="sm:text-right font-mono text-[11px] text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 px-2.5 py-1 rounded-md border border-emerald-200 dark:border-emerald-800/50 self-start sm:self-auto font-medium">
                      {item.estimatedRiskReduction}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};
