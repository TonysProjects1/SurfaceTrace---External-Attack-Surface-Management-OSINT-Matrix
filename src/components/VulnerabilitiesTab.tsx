import React, { useState, useEffect } from 'react';
import { EasmScanResult, VulnerabilityBreachData, BreachIncident, GitExposureDork } from '../types';
import { 
  ShieldAlert, AlertTriangle, CheckCircle2, Lock, Terminal, 
  ExternalLink, Copy, Check, RefreshCw, Database, Key, 
  Bug, Eye, Flame, Shield, Search, ArrowUpRight, Cpu, 
  Layers, UserCheck, AlertCircle, Sparkles, Filter, FileText, Calculator, Building2
} from 'lucide-react';
import { CredentialDrilldownModal } from './CredentialDrilldownModal';

interface VulnerabilitiesTabProps {
  scan: EasmScanResult;
  initialData?: VulnerabilityBreachData;
}

export const VulnerabilitiesTab: React.FC<VulnerabilitiesTabProps> = ({ scan, initialData }) => {
  const [data, setData] = useState<VulnerabilityBreachData | null>(initialData || scan.vulnerabilities || null);
  const [isLoading, setIsLoading] = useState<boolean>(!data);
  const [activeSubTab, setActiveSubTab] = useState<'stealer' | 'hibp' | 'kanonymity' | 'gitdorks' | 'playbook'>('stealer');
  const [copiedQuery, setCopiedQuery] = useState<string | null>(null);
  const [cliCopied, setCliCopied] = useState<string | null>(null);
  const [endpointCopied, setEndpointCopied] = useState<string | null>(null);
  const [urlFilter, setUrlFilter] = useState<'all' | 'Employee' | 'Client'>('all');

  // Drilldown & Management Report Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalInitialTab, setModalInitialTab] = useState<'calculation' | 'executive' | 'endpoints'>('calculation');

  const openDrilldown = (tab: 'calculation' | 'executive' | 'endpoints') => {
    setModalInitialTab(tab);
    setIsModalOpen(true);
  };

  // K-Anonymity Tester State
  const [testPasswordInput, setTestPasswordInput] = useState<string>('');
  const [isCheckingHash, setIsCheckingHash] = useState<boolean>(false);
  const [hashCheckResult, setHashCheckResult] = useState<{
    tested: boolean;
    sha1: string;
    prefix: string;
    suffix: string;
    pwnCount: number;
    isPwned: boolean;
  } | null>(null);

  const fetchVulnerabilityIntel = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/vulnerabilities/credentials?domain=${encodeURIComponent(scan.domain)}`);
      if (res.ok) {
        const intel: VulnerabilityBreachData = await res.json();
        setData(intel);
      }
    } catch (err) {
      console.error('Failed to fetch breach intel:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!data || data.domain !== scan.domain) {
      fetchVulnerabilityIntel();
    }
  }, [scan.domain]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQuery(id);
    setTimeout(() => setCopiedQuery(null), 2000);
  };

  const copyCli = (command: string, id: string) => {
    navigator.clipboard.writeText(command);
    setCliCopied(id);
    setTimeout(() => setCliCopied(null), 2000);
  };

  // Perform Client-Side SHA-1 k-Anonymity Hash Check
  const handleCheckPassword = async (pwdToCheck?: string) => {
    const targetPassword = pwdToCheck !== undefined ? pwdToCheck : testPasswordInput;
    if (!targetPassword) return;

    setIsCheckingHash(true);
    setHashCheckResult(null);

    try {
      // 1. Calculate SHA-1 in browser via Web Cryptography API
      const encoder = new TextEncoder();
      const data = encoder.encode(targetPassword);
      const hashBuffer = await crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha1 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5);

      // 2. Query k-anonymity endpoint with ONLY first 5 chars
      const response = await fetch('/api/vulnerabilities/check-password-hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix })
      });

      if (!response.ok) {
        throw new Error('Hash check failed');
      }

      const resJson = await response.json();
      const matches: { hashSuffix: string; count: number }[] = resJson.matches || [];

      // 3. Compare remaining 35 characters client-side (no plain password ever transmitted)
      const foundMatch = matches.find(m => m.hashSuffix.toUpperCase() === suffix.toUpperCase());
      const pwnCount = foundMatch ? foundMatch.count : 0;

      setHashCheckResult({
        tested: true,
        sha1,
        prefix,
        suffix,
        pwnCount,
        isPwned: pwnCount > 0
      });
    } catch (err) {
      console.error('K-Anonymity check failed:', err);
    } finally {
      setIsCheckingHash(false);
    }
  };

  const stealerData = data?.stealerIntel;
  const breaches = data?.breaches || [];
  const dorks = data?.dorks || [];

  return (
    <div className="space-y-6">
      {/* 1. Header Card with Live Status & APIs Badges */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs transition-colors">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 flex items-center gap-1">
                <Flame className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
                <span>BREACH & IDENTITY TELEMETRY</span>
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                Domain: <code className="font-semibold text-slate-800 dark:text-slate-200">{scan.domain}</code>
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500">
                • Updated {data?.lastQueriedAt ? new Date(data.lastQueriedAt).toLocaleTimeString() : 'Just now'}
              </span>
            </div>

            <h3 className="text-xl font-extrabold text-slate-900 dark:text-white tracking-tight flex items-center gap-2">
              Vulnerabilities & Leaked Credential Exposure
            </h3>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 max-w-3xl leading-relaxed">
              Continuous threat intelligence aggregation across <strong>Have I Been Pwned</strong> (historical breach catalog), <strong>Hudson Rock Cavalier</strong> (active RedLine, Lumma, Vidar infostealer botnets), and <strong>GitHub OSINT Secret Reconnaissance</strong> to expose leaked corporate credentials and hijacked session tokens.
            </p>
          </div>

          {/* Right Action & Risk Meter */}
          <div className="flex items-center gap-4 shrink-0">
            <div className="text-right">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Credential Exposure Risk
              </div>
              <div className="flex items-center gap-2 mt-0.5 justify-end">
                <span className={`text-xl font-bold font-mono ${
                  (data?.riskScore || 0) >= 70 ? 'text-red-600 dark:text-red-400' :
                  (data?.riskScore || 0) >= 40 ? 'text-orange-600 dark:text-orange-400' :
                  'text-emerald-600 dark:text-emerald-400'
                }`}>
                  {data?.riskScore || 0}/100
                </span>
                <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase ${
                  data?.status === 'CRITICAL_RISK' ? 'bg-red-100 text-red-800 dark:bg-red-950/80 dark:text-red-300' :
                  data?.status === 'WARNING' ? 'bg-orange-100 text-orange-800 dark:bg-orange-950/80 dark:text-orange-300' :
                  'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/80 dark:text-emerald-300'
                }`}>
                  {data?.status === 'CRITICAL_RISK' ? 'Critical Exposure' :
                   data?.status === 'WARNING' ? 'Elevated Risk' : 'Low Exposure'}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => openDrilldown('executive')}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
                title="Generate Executive Threat & Management Review Briefing"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Executive Briefing</span>
              </button>

              <button
                onClick={fetchVulnerabilityIntel}
                disabled={isLoading}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer disabled:opacity-50"
                title="Refresh breach and stealer telemetry"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-blue-600' : 'text-slate-500'}`} />
                <span>{isLoading ? 'Querying APIs...' : 'Refresh Intel'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Integrated Free-Tier OSINT APIs Badge Bar */}
        <div className="mt-5 pt-4 border-t border-slate-100 dark:border-slate-800 flex flex-wrap items-center gap-3 text-xs">
          <span className="font-semibold text-slate-500 dark:text-slate-400 text-[11px] uppercase tracking-wider">
            Connected Free OSINT Feeds:
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[11px]">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
            <span>Have I Been Pwned (v3 Breaches API)</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[11px]">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
            <span>Hudson Rock Cavalier (Stealer Botnet Telemetry)</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[11px]">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
            <span>HIBP Pwned Passwords (k-Anonymity SHA-1)</span>
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[11px]">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
            <span>GitHub Secret Reconnaissance Dorks</span>
          </span>
        </div>
      </div>

      {/* 2. Top 4 KPI Metrics Cards - Interactive Drill-Downs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Infostealer Employees */}
        <div 
          onClick={() => openDrilldown('endpoints')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrilldown('endpoints'); } }}
          className="bg-white dark:bg-slate-900 hover:bg-slate-50/80 dark:hover:bg-slate-800/60 border border-slate-200 dark:border-slate-800 hover:border-red-400 dark:hover:border-red-500/80 rounded-xl p-4 shadow-xs transition-all cursor-pointer group flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider">Infected Corporate Hosts</span>
              <Bug className="w-4 h-4 text-red-500 group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
              {stealerData?.employeesInfected !== undefined ? stealerData.employeesInfected : '—'}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              {stealerData?.employeesInfected ? (
                <span className="text-red-600 dark:text-red-400 font-semibold">
                  Active employee malware infections
                </span>
              ) : (
                'Zero corporate hosts indexed'
              )}
            </p>
          </div>
          <div className="pt-2.5 mt-2 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-red-600 dark:group-hover:text-red-400 font-medium flex items-center justify-between">
            <span>Drill-down infected endpoints</span>
            <span className="font-bold">→</span>
          </div>
        </div>

        {/* Metric 2: Documented Breaches */}
        <div 
          onClick={() => openDrilldown('calculation')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrilldown('calculation'); } }}
          className="bg-white dark:bg-slate-900 hover:bg-slate-50/80 dark:hover:bg-slate-800/60 border border-slate-200 dark:border-slate-800 hover:border-orange-400 dark:hover:border-orange-500/80 rounded-xl p-4 shadow-xs transition-all cursor-pointer group flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider">Documented Breaches</span>
              <Database className="w-4 h-4 text-orange-500 group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
              {breaches.length}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              {breaches.length > 0 ? (
                <span className="text-orange-600 dark:text-orange-400 font-semibold">
                  Cataloged in HIBP database
                </span>
              ) : (
                '0 direct domain breaches found'
              )}
            </p>
          </div>
          <div className="pt-2.5 mt-2 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-orange-600 dark:group-hover:text-orange-400 font-medium flex items-center justify-between">
            <span>Verify HIBP catalog audit</span>
            <span className="font-bold">→</span>
          </div>
        </div>

        {/* Metric 3: Total Compromised Accounts - Highlighted with Calculation Pill */}
        <div 
          onClick={() => openDrilldown('calculation')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrilldown('calculation'); } }}
          className="bg-white dark:bg-slate-900 hover:bg-slate-50/80 dark:hover:bg-slate-800/60 border-2 border-blue-500/50 dark:border-blue-500/60 hover:border-blue-500 dark:hover:border-blue-400 rounded-xl p-4 shadow-xs transition-all cursor-pointer group flex flex-col justify-between relative overflow-hidden"
        >
          <div className="absolute top-0 right-0 bg-blue-600 text-white text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded-bl-lg tracking-wider">
            Audit Calculation
          </div>
          <div>
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider">Total Leaked Records</span>
              <Lock className="w-4 h-4 text-blue-500 group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-2xl font-bold font-mono text-blue-600 dark:text-blue-400 truncate">
              {data?.totalExposedCredentials ? data.totalExposedCredentials.toLocaleString() : '0'}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 truncate">
              Employee + client/user credential sets
            </p>
          </div>
          <div className="pt-2.5 mt-2 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-blue-600 dark:text-blue-400 font-semibold flex items-center justify-between">
            <span>How was this determined?</span>
            <span className="font-bold">→</span>
          </div>
        </div>

        {/* Metric 4: Stealer Botnet Families */}
        <div 
          onClick={() => openDrilldown('endpoints')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrilldown('endpoints'); } }}
          className="bg-white dark:bg-slate-900 hover:bg-slate-50/80 dark:hover:bg-slate-800/60 border border-slate-200 dark:border-slate-800 hover:border-purple-400 dark:hover:border-purple-500/80 rounded-xl p-4 shadow-xs transition-all cursor-pointer group flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider">Stealer Strains Active</span>
              <Cpu className="w-4 h-4 text-purple-500 group-hover:scale-110 transition-transform" />
            </div>
            <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
              {stealerData?.stealerFamilies ? Object.keys(stealerData.stealerFamilies).length : 0}
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              RedLine, Lumma, Vidar, Raccoon
            </p>
          </div>
          <div className="pt-2.5 mt-2 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-purple-600 dark:group-hover:text-purple-400 font-medium flex items-center justify-between">
            <span>Drill-down threat families</span>
            <span className="font-bold">→</span>
          </div>
        </div>
      </div>

      {/* 3. Sub-Navigation Tabs */}
      <div className="flex items-center gap-1.5 border-b border-slate-200 dark:border-slate-800 overflow-x-auto pb-px">
        <button
          onClick={() => setActiveSubTab('stealer')}
          className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeSubTab === 'stealer'
              ? 'bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border-t-2 border-x border-b-0 border-blue-600 dark:border-blue-500 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Bug className="w-3.5 h-3.5 text-red-500" />
          <span>Infostealer & Dark Web Intel</span>
          {stealerData?.employeesInfected ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-600 text-white font-bold">
              {stealerData.employeesInfected}
            </span>
          ) : null}
        </button>

        <button
          onClick={() => setActiveSubTab('hibp')}
          className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeSubTab === 'hibp'
              ? 'bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border-t-2 border-x border-b-0 border-blue-600 dark:border-blue-500 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Database className="w-3.5 h-3.5 text-orange-500" />
          <span>Have I Been Pwned Breaches</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 font-bold">
            {breaches.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('kanonymity')}
          className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeSubTab === 'kanonymity'
              ? 'bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border-t-2 border-x border-b-0 border-blue-600 dark:border-blue-500 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Key className="w-3.5 h-3.5 text-emerald-500" />
          <span>Interactive K-Anonymity Tester</span>
        </button>

        <button
          onClick={() => setActiveSubTab('gitdorks')}
          className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeSubTab === 'gitdorks'
              ? 'bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border-t-2 border-x border-b-0 border-blue-600 dark:border-blue-500 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Search className="w-3.5 h-3.5 text-purple-500" />
          <span>Git Secret Exposure Dorks</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 font-bold">
            {dorks.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('playbook')}
          className={`px-3.5 py-2 text-xs font-semibold rounded-t-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
            activeSubTab === 'playbook'
              ? 'bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border-t-2 border-x border-b-0 border-blue-600 dark:border-blue-500 shadow-xs'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-blue-500" />
          <span>Defense & Hardening Playbook</span>
        </button>
      </div>

      {/* 4. Tab Content Panels */}

      {/* Panel A: Infostealer & Dark Web Intel */}
      {activeSubTab === 'stealer' && (
        <div className="space-y-6">
          {/* Critical Explanatory Callout */}
          <div className="bg-red-50/70 dark:bg-red-950/30 border border-red-200 dark:border-red-900/60 rounded-xl p-4 sm:p-5 text-xs text-red-800 dark:text-red-300">
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="font-bold text-sm text-red-900 dark:text-red-200">
                  Infostealer Malware Mechanics: Session Hijacking Beyond Passwords
                </div>
                <p className="leading-relaxed">
                  Unlike traditional database dumps containing salted password hashes, modern infostealer malware (RedLine, Lumma, Vidar, Raccoon) dumps live SQLite browser databases from infected employee workstations. This extracts <strong>active session cookies, SSO authorization tokens, and saved autofill credentials</strong>. Adversaries import these session cookies into browser extensions to bypass Multi-Factor Authentication (MFA) entirely.
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Targeted Portals & Endpoints */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3 gap-2">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                    <Flame className="w-4 h-4 text-red-500" />
                    Targeted Corporate Login Endpoints
                  </h4>
                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    Hudson Rock Cavalier Telemetry
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-950 p-0.5 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px]">
                    <button
                      onClick={() => setUrlFilter('all')}
                      className={`px-2 py-0.5 rounded font-medium transition-colors cursor-pointer ${
                        urlFilter === 'all'
                          ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs font-semibold'
                          : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      All ({(stealerData?.topCompromisedUrls || []).length})
                    </button>
                    <button
                      onClick={() => setUrlFilter('Employee')}
                      className={`px-2 py-0.5 rounded font-medium transition-colors cursor-pointer ${
                        urlFilter === 'Employee'
                          ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 font-bold shadow-xs'
                          : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      Employee
                    </button>
                    <button
                      onClick={() => setUrlFilter('Client')}
                      className={`px-2 py-0.5 rounded font-medium transition-colors cursor-pointer ${
                        urlFilter === 'Client'
                          ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 font-bold shadow-xs'
                          : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      Client
                    </button>
                  </div>

                  <button
                    onClick={() => openDrilldown('endpoints')}
                    className="p-1 text-slate-400 hover:text-blue-500 dark:hover:text-blue-400 cursor-pointer"
                    title="Open Full Endpoint Drilldown"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {stealerData?.topCompromisedUrls && stealerData.topCompromisedUrls.length > 0 ? (
                <div className="space-y-2">
                  {stealerData.topCompromisedUrls
                    .filter(endpoint => urlFilter === 'all' || endpoint.type === urlFilter)
                    .map((endpoint, idx) => (
                    <div 
                      key={idx}
                      className="p-3 rounded-xl bg-slate-100/90 dark:bg-slate-950/80 hover:bg-slate-200/70 dark:hover:bg-slate-900 border border-slate-200 dark:border-slate-800/90 flex items-center justify-between gap-3 text-xs transition-colors group"
                    >
                      <div className="flex items-center gap-2.5 truncate min-w-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 border ${
                          endpoint.type === 'Employee' 
                            ? 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30' 
                            : 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30'
                        }`}>
                          {endpoint.type}
                        </span>
                        <code className="text-slate-800 dark:text-slate-100 font-mono text-xs truncate select-all">
                          {endpoint.url}
                        </code>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(endpoint.url);
                            setEndpointCopied(endpoint.url);
                            setTimeout(() => setEndpointCopied(null), 2000);
                          }}
                          className="p-1 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                          title="Copy Endpoint URL"
                        >
                          {endpointCopied === endpoint.url ? (
                            <Check className="w-3.5 h-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <span className="px-2.5 py-1 rounded-md bg-slate-200/80 dark:bg-slate-800 text-slate-900 dark:text-slate-100 font-mono text-[11px] shrink-0 font-bold border border-slate-300 dark:border-slate-700">
                          {endpoint.occurrence.toLocaleString()} hit{endpoint.occurrence > 1 ? 's' : ''}
                        </span>
                      </div>
                    </div>
                  ))}
                  {stealerData.topCompromisedUrls.filter(endpoint => urlFilter === 'all' || endpoint.type === urlFilter).length === 0 && (
                    <div className="py-6 text-center text-xs text-slate-500 dark:text-slate-400">
                      No endpoints matching the "{urlFilter}" filter.
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500 dark:text-slate-400 space-y-1">
                  <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto" />
                  <p className="font-semibold text-slate-800 dark:text-slate-200">
                    No active corporate URL credentials captured in stealer logs
                  </p>
                  <p className="text-[11px]">
                    No corporate accounts for {scan.domain} were detected in recent botnet harvests.
                  </p>
                </div>
              )}

              {/* Infection Timestamps */}
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-100/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 block">
                    Last Employee Infection
                  </span>
                  <span className="font-mono text-slate-900 dark:text-slate-100 font-semibold text-xs mt-0.5 block">
                    {stealerData?.lastEmployeeCompromised 
                      ? new Date(stealerData.lastEmployeeCompromised).toLocaleDateString()
                      : 'None recorded'}
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-slate-100/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] uppercase font-bold text-slate-500 dark:text-slate-400 block">
                    Last User / Client Infection
                  </span>
                  <span className="font-mono text-slate-900 dark:text-slate-100 font-semibold text-xs mt-0.5 block">
                    {stealerData?.lastUserCompromised 
                      ? new Date(stealerData.lastUserCompromised).toLocaleDateString()
                      : 'None recorded'}
                  </span>
                </div>
              </div>
            </div>

            {/* Stealer Families Distribution */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-500" />
                  Active Infostealer Malware Strains
                </h4>
                <span className="text-[11px] font-mono text-slate-500">
                  Botnet Distribution
                </span>
              </div>

              {stealerData?.stealerFamilies && Object.keys(stealerData.stealerFamilies).length > 0 ? (
                <div className="space-y-2.5">
                  {(Object.entries(stealerData.stealerFamilies) as [string, number][])
                    .sort(([, a], [, b]) => Number(b) - Number(a))
                    .slice(0, 7)
                    .map(([family, count]) => {
                      const counts = Object.values(stealerData.stealerFamilies).map(v => Number(v) || 0);
                      const max = Math.max(...counts, 1);
                      const countNum = Number(count) || 0;
                      const percent = Math.round((countNum / max) * 100);
                      return (
                        <div key={family} className="space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-red-500"></span>
                              {family}
                            </span>
                            <span className="font-mono text-slate-600 dark:text-slate-400 text-[11px]">
                              {countNum.toLocaleString()} credentials
                            </span>
                          </div>
                          <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-red-500 rounded-full transition-all" 
                              style={{ width: `${percent}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500 dark:text-slate-400">
                  <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto mb-1" />
                  <span>No infostealer botnet malware telemetry detected for this domain.</span>
                </div>
              )}

              {/* OSINT Reperformance Command */}
              <div className="pt-3 border-t border-slate-100 dark:border-slate-800">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 mb-1.5">
                  <span>Reperformance CLI Query (Hudson Rock Free API):</span>
                  <button
                    onClick={() => copyCli(`curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${scan.domain}" | jq`, 'hudson-cli')}
                    className="hover:text-blue-500 cursor-pointer flex items-center gap-1"
                  >
                    {cliCopied === 'hudson-cli' ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                    <span>{cliCopied === 'hudson-cli' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-2 rounded bg-slate-950 text-slate-300 font-mono text-[11px] overflow-x-auto border border-slate-800">
                  curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={scan.domain}" | jq
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Panel B: Have I Been Pwned Breaches */}
      {activeSubTab === 'hibp' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl">
            <div>
              <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-orange-500" />
                Have I Been Pwned Corporate Domain Incidents
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Querying <code className="font-mono text-slate-800 dark:text-slate-200">api.haveibeenpwned.com/v3/breaches?domain={scan.domain}</code>
              </p>
            </div>
            <button
              onClick={() => copyCli(`curl -s "https://haveibeenpwned.com/api/v3/breaches?domain=${scan.domain}" -H "User-Agent: SurfaceTrace-EASM" | jq`, 'hibp-cli')}
              className="px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-mono flex items-center gap-1.5 cursor-pointer shrink-0"
            >
              {cliCopied === 'hibp-cli' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
              <span>{cliCopied === 'hibp-cli' ? 'Copied CLI Command' : 'Copy HIBP cURL'}</span>
            </button>
          </div>

          {breaches.length > 0 ? (
            <div className="grid grid-cols-1 gap-4">
              {breaches.map((breach) => (
                <div 
                  key={breach.Name} 
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
                    <div className="flex items-center gap-3">
                      {breach.LogoPath ? (
                        <img 
                          src={breach.LogoPath} 
                          alt={breach.Title} 
                          className="w-10 h-10 rounded-lg object-contain bg-slate-100 dark:bg-slate-800 p-1 border border-slate-200 dark:border-slate-700" 
                          referrerPolicy="no-referrer"
                        />
                      ) : (
                        <div className="w-10 h-10 rounded-lg bg-orange-100 dark:bg-orange-950/60 text-orange-600 dark:text-orange-400 flex items-center justify-center font-bold">
                          <Database className="w-5 h-5" />
                        </div>
                      )}
                      <div>
                        <h4 className="font-extrabold text-base text-slate-900 dark:text-white">
                          {breach.Title}
                        </h4>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                          <span>Breach Date: <strong>{breach.BreachDate}</strong></span>
                          <span>•</span>
                          <span>Exposed Accounts: <strong className="text-red-600 dark:text-red-400">{breach.PwnCount.toLocaleString()}</strong></span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                      {breach.IsVerified && (
                        <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-semibold">
                          Verified Incident
                        </span>
                      )}
                      {breach.IsFabricated && (
                        <span className="px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                          Fabricated
                        </span>
                      )}
                      {breach.IsSensitive && (
                        <span className="px-2 py-0.5 rounded bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-semibold">
                          Sensitive Data
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
                    {breach.Description}
                  </p>

                  {/* Compromised Data Classes Badges */}
                  <div>
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block mb-1.5">
                      Exposed Data Classes:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {breach.DataClasses.map((dc) => (
                        <span 
                          key={dc}
                          className="px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200/80 dark:border-slate-700 text-xs font-mono"
                        >
                          {dc}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <h4 className="font-bold text-base text-slate-900 dark:text-white">
                Zero Direct Domain Breaches Documented in Have I Been Pwned
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-lg mx-auto leading-relaxed">
                The authoritative HIBP breach repository contains no documented direct compromise events specifically cataloged under <code className="font-mono text-slate-800 dark:text-slate-200">{scan.domain}</code>. Note: corporate employees may still appear in third-party service breaches (e.g. LinkedIn, Dropbox) using their corporate email addresses.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Panel C: Interactive K-Anonymity Tester */}
      {activeSubTab === 'kanonymity' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-6">
          <div>
            <h4 className="font-extrabold text-base text-slate-900 dark:text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              Interactive K-Anonymity Credential & Hash Verification
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-3xl leading-relaxed">
              Demonstrating the mathematical standard for zero-knowledge breached password validation. Using <strong>k-Anonymity</strong>, the SHA-1 hash is computed inside your browser. Only the <strong>first 5 characters</strong> are queried against the HIBP Pwned Passwords range API, ensuring your cleartext string is never transmitted across the network.
            </p>
          </div>

          {/* Test Input & Presets */}
          <div className="space-y-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 p-4 rounded-xl">
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block">
              Test Password or Corporate Baseline Pattern:
            </label>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={testPasswordInput}
                onChange={(e) => setTestPasswordInput(e.target.value)}
                placeholder="Enter password (e.g. Summer2024!, Password123, or custom string)"
                className="flex-1 px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={() => handleCheckPassword()}
                disabled={isCheckingHash || !testPasswordInput.trim()}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition-colors cursor-pointer disabled:opacity-50 flex items-center justify-center gap-1.5 shrink-0"
              >
                {isCheckingHash ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                <span>{isCheckingHash ? 'Validating Range...' : 'Check Against 850M+ Leaks'}</span>
              </button>
            </div>

            {/* Common Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-2 text-xs">
              <span className="text-[11px] text-slate-500 dark:text-slate-400">Quick Test Samples:</span>
              {['P@ssword1', 'Welcome123!', 'Admin2024!', 'Summer2023!', 'qwerty12345'].map((sample) => (
                <button
                  key={sample}
                  onClick={() => {
                    setTestPasswordInput(sample);
                    handleCheckPassword(sample);
                  }}
                  className="px-2 py-0.5 rounded bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-mono text-[11px] cursor-pointer transition-colors"
                >
                  {sample}
                </button>
              ))}
            </div>
          </div>

          {/* Test Result Display */}
          {hashCheckResult && (
            <div className={`p-5 rounded-xl border text-xs space-y-3 transition-colors ${
              hashCheckResult.isPwned
                ? 'bg-red-50/80 dark:bg-red-950/40 border-red-200 dark:border-red-900/60 text-red-900 dark:text-red-200'
                : 'bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-900/60 text-emerald-900 dark:text-emerald-200'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-sm">
                  {hashCheckResult.isPwned ? (
                    <>
                      <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400" />
                      <span>CRITICAL LEAK: Compromised in {hashCheckResult.pwnCount.toLocaleString()} Public Breaches</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                      <span>Zero Recorded Breaches: Not found in public leak repositories</span>
                    </>
                  )}
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white/80 dark:bg-slate-900/80 border border-current/20">
                  k-Anonymity Verified
                </span>
              </div>

              <div className="font-mono text-[11px] space-y-1 bg-white/60 dark:bg-slate-950/60 p-3 rounded-lg border border-current/15">
                <div>Full SHA-1 (Computed locally in browser): <code>{hashCheckResult.sha1}</code></div>
                <div>Public Query Range (Sent to API): <code className="font-bold text-blue-600 dark:text-blue-400">{hashCheckResult.prefix}</code> (k-Anonymity model)</div>
                <div>Private Client Suffix: <code>{hashCheckResult.suffix}</code> (Evaluated locally against returned bucket)</div>
              </div>

              <p className="text-xs leading-relaxed">
                {hashCheckResult.isPwned
                  ? `This credential pattern has been observed ${hashCheckResult.pwnCount.toLocaleString()} times in historical breach corpora. Under NIST SP 800-63B and PCI-DSS Requirement 8.3.6, enterprise authenticators must reject any passwords appearing in compromised credential databases.`
                  : 'This string was not identified in the 850+ million breached passwords dataset. Ensure corporate complexity and length requirements (minimum 15 characters) remain enforced.'}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Panel D: Git Secret Exposure Dorks */}
      {activeSubTab === 'gitdorks' && (
        <div className="space-y-4">
          <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl flex items-center justify-between">
            <div>
              <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                <Search className="w-4 h-4 text-purple-500" />
                Targeted Public Git Secret Reconnaissance
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Pre-compiled queries targeting accidentally committed tokens, configuration files, and cloud credentials referencing <code className="font-mono text-slate-800 dark:text-slate-200">{scan.domain}</code>
              </p>
            </div>
            <span className="text-xs font-mono text-slate-500 hidden sm:block">
              {dorks.length} reconnaissance vectors
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {dorks.map((dork, idx) => (
              <div 
                key={idx}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-xs space-y-3 flex flex-col justify-between"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900 dark:text-white">
                      {dork.label}
                    </span>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      dork.severity === 'CRITICAL' ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300' :
                      dork.severity === 'HIGH' ? 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300' :
                      'bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                    }`}>
                      {dork.severity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    {dork.riskDescription}
                  </p>

                  <div className="p-2 rounded bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto border border-slate-800 flex items-center justify-between gap-2">
                    <code className="truncate">{dork.query}</code>
                    <button
                      onClick={() => copyToClipboard(dork.query, `dork-${idx}`)}
                      className="text-slate-400 hover:text-white shrink-0 cursor-pointer"
                      title="Copy Query"
                    >
                      {copiedQuery === `dork-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400">
                    Category: {dork.category}
                  </span>
                  <a
                    href={dork.searchUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  >
                    <span>Execute on GitHub</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Panel E: Defense & Hardening Playbook */}
      {activeSubTab === 'playbook' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-6">
          <div>
            <h4 className="font-extrabold text-base text-slate-900 dark:text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Actionable Credential Defense & Stealer Mitigation Roadmap
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 max-w-3xl leading-relaxed">
              Standard SMS and mobile push OTP are insufficient to stop infostealer malware, which exfiltrates established session tokens. Follow this prioritized remediation sequence to defend the enterprise perimeter:
            </p>
          </div>

          <div className="space-y-4">
            {(data?.remediationRoadmap || []).map((step) => (
              <div 
                key={step.priority}
                className="p-4 rounded-xl bg-slate-50 dark:bg-slate-850 border border-slate-200/80 dark:border-slate-800 space-y-2"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-xs shrink-0">
                      {step.priority}
                    </span>
                    <h5 className="font-bold text-sm text-slate-900 dark:text-white">
                      {step.title}
                    </h5>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 shrink-0">
                    {step.standard}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed pl-8">
                  {step.action}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Credential Drilldown & Executive Management Review Modal */}
      <CredentialDrilldownModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        domain={scan.domain}
        data={data}
        breaches={breaches}
        stealerData={stealerData}
        initialTab={modalInitialTab}
      />
    </div>
  );
};
