import React, { useState } from 'react';
import { 
  Shield, Globe, Search, Lock, Terminal, ArrowRight, Layers, 
  Cpu, CheckCircle2, AlertTriangle, Server, Eye, BookOpen, 
  FileText, Sparkles, Radio, Network, Database, Mail, Compass,
  Info, KeyRound, ExternalLink, HelpCircle, ArrowUpRight, Scale,
  ShieldCheck, Check, ArrowDown, Building2, Target, Play, 
  ChevronRight, ClipboardList, Flame, Zap
} from 'lucide-react';
import { OsintDirectoryTab } from './OsintDirectoryTab';

interface AboutTabProps {
  onNavigateTab: (tab: string) => void;
  currentDomain?: string;
  onScanDomain?: (domain: string) => void;
}

export const AboutTab: React.FC<AboutTabProps> = ({ onNavigateTab, currentDomain = '', onScanDomain }) => {
  const [activeSection, setActiveSection] = useState<'how-to-use' | 'legal-queries' | 'overview' | 'capabilities' | 'pipeline' | 'osint-dir' | 'mitre' | 'compliance'>('how-to-use');

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Hero Header */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs relative overflow-hidden transition-colors">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl pointer-events-none"></div>
        <div className="relative z-10 space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300 text-xs font-semibold">
            <Scale className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
            <span>Platform Documentation & User Guide</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
            SurfaceTrace Platform Architecture & Operator Guide
          </h1>

          <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 max-w-4xl leading-relaxed">
            SurfaceTrace is an enterprise-grade <strong>External Attack Surface Management (EASM)</strong> and <strong>Open Source Intelligence (OSINT)</strong> platform. 
            All telemetry is gathered via <strong>passive reconnaissance</strong> and public transparency registries with zero exploit attempts. Review how to use the platform, an end-to-end target company case study, legal queries, and regulatory mappings below.
          </p>

          <div className="pt-2 flex flex-wrap gap-3">
            <button
              onClick={() => onNavigateTab('overview')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Return to Live Scan Report</span>
            </button>
            <button
              onClick={() => onNavigateTab('sqlite')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 text-xs font-semibold border border-emerald-200 dark:border-emerald-800 transition-colors cursor-pointer"
            >
              <Database className="w-3.5 h-3.5" />
              <span>Inspect Raw SQLite Network Logs</span>
            </button>
          </div>
        </div>
      </div>

      {/* Internal Navigation Sub-Bar */}
      <div className="flex items-center space-x-1 border-b border-slate-200 dark:border-slate-800 pb-1 overflow-x-auto">
        {[
          { id: 'how-to-use', label: '1. How to Use & Target Case Study' },
          { id: 'legal-queries', label: '2. Legal Confirmation & Exact Network Queries' },
          { id: 'compliance', label: '3. NIST & Regulatory Controls' },
          { id: 'overview', label: '4. What is EASM?' },
          { id: 'capabilities', label: '5. Core Capabilities & SQLite' },
          { id: 'pipeline', label: '6. Technical Pipeline' },
          { id: 'osint-dir', label: '7. Curated OSINT Directory' },
          { id: 'mitre', label: '8. MITRE ATT&CK Mapping' },
        ].map((sec) => (
          <button
            key={sec.id}
            onClick={() => setActiveSection(sec.id as any)}
            className={`px-3.5 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-colors cursor-pointer ${
              activeSection === sec.id
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60'
            }`}
          >
            {sec.label}
          </button>
        ))}
      </div>

      {/* SECTION 1: HOW TO USE & TARGET CASE STUDY */}
      {activeSection === 'how-to-use' && (
        <div className="space-y-8 animate-in fade-in-50">
          {/* Executive Overview Banner */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs space-y-4 transition-colors">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-5">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 uppercase tracking-wider">
                    Operator Manual & Case Study
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                    SurfaceTrace Field Guide v2.4
                  </span>
                </div>
                <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                  How to Use SurfaceTrace: Operational Blueprint & Target Walkthrough
                </h2>
                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-3xl leading-relaxed">
                  A comprehensive guide detailing how security engineers, compliance auditors, and threat analysts leverage SurfaceTrace to map external perimeters, triage critical exposures, satisfy federal and industry compliance benchmarks, and preserve forensic audit logs in client-side SQLite.
                </p>
              </div>

              {/* Quick Launch Sandbox */}
              <div className="flex flex-col sm:flex-row lg:flex-col items-start lg:items-end gap-2 shrink-0">
                <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Test-Drive with Live Targets:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { domain: 'cloudflare.com', label: 'Cloudflare' },
                    { domain: 'stripe.com', label: 'Stripe' },
                    { domain: 'github.com', label: 'GitHub' },
                    { domain: 'reddit.com', label: 'Reddit' }
                  ].map((target) => (
                    <button
                      key={target.domain}
                      onClick={() => {
                        if (onScanDomain) {
                          onScanDomain(target.domain);
                        } else {
                          onNavigateTab('overview');
                        }
                      }}
                      className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-blue-50 dark:bg-slate-800 dark:hover:bg-blue-950/60 text-slate-700 hover:text-blue-600 dark:text-slate-300 dark:hover:text-blue-400 text-xs font-medium border border-slate-200 dark:border-slate-700 transition-colors flex items-center gap-1 cursor-pointer"
                    >
                      <Play className="w-3 h-3 text-blue-500 fill-blue-500/20" />
                      <span>{target.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick 3-Phase Lifecycle Badges */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="flex items-center gap-2 text-xs font-bold text-blue-600 dark:text-blue-400">
                  <div className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900/60 flex items-center justify-center text-[10px]">1</div>
                  <span>Zero-Touch Reconnaissance</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Enter apex domain. 8 parallel non-intrusive feeds query DoH, crt.sh CT logs, RDAP, and BGP ASNs in under 4 seconds.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="flex items-center gap-2 text-xs font-bold text-purple-600 dark:text-purple-400">
                  <div className="w-5 h-5 rounded-full bg-purple-100 dark:bg-purple-900/60 flex items-center justify-center text-[10px]">2</div>
                  <span>Vulnerability & Compliance Triage</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Uncover dangling CNAME takeovers, DMARC/SPF flaws, and missing HSTS. Automatically map to NIST, CIS, ISO, and PCI-DSS.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald-600 dark:text-emerald-400">
                  <div className="w-5 h-5 rounded-full bg-emerald-100 dark:bg-emerald-900/60 flex items-center justify-center text-[10px]">3</div>
                  <span>Forensic Proof & AI Modeling</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Store immutable logs in browser-side WASM SQLite, execute ad-hoc SQL queries, and synthesize AI red-team attack vectors.
                </p>
              </div>
            </div>
          </div>

          {/* PART 1: STEP-BY-STEP OPERATIONAL GUIDE */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs space-y-6 transition-colors">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
              <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <ClipboardList className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <span>Part 1: The Step-by-Step Operational Workflow</span>
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Follow this proven 8-step methodology to assess any organization's external perimeter
              </p>
            </div>

            <div className="space-y-6">
              {/* Step 1 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  01
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Input Target Apex Domain & Automatic Normalization</span>
                    <span className="text-[11px] font-mono text-blue-600 dark:text-blue-400 font-semibold">Discovery Ingestion</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Always enter the apex organization domain (e.g., <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded font-mono">company.com</code>). 
                    If you paste a complete URL such as <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded font-mono">https://portal.company.com/login?ref=1</code>, 
                    SurfaceTrace's input sanitizer automatically strips protocols, port numbers, URI paths, and query arguments to isolate the target root. Starting at the apex ensures complete enumeration of all subordinate DNS delegations, Wildcards, and Certificate Authority issuance logs.
                  </p>
                </div>
              </div>

              {/* Step 2 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  02
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Automated Multi-Source Passive Telemetry Pipeline</span>
                    <span className="text-[11px] font-mono text-purple-600 dark:text-purple-400 font-semibold">&lt;4000ms SLA</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Once initiated, SurfaceTrace executes 8 parallel queries against public cryptographic and network ledgers:
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-[11px] text-slate-600 dark:text-slate-300">
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                      <strong>• Certificate Transparency (crt.sh):</strong> Harvests all active and historical X.509 certificates to discover hidden staging and dev subdomains.
                    </div>
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                      <strong>• Authoritative DNS-over-HTTPS (DoH):</strong> Resolves A, AAAA, CNAME, MX, TXT, and CAA records via Cloudflare (1.1.1.1) and Google (8.8.8.8).
                    </div>
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                      <strong>• RDAP / WHOIS Registrar Feeds:</strong> Validates domain lifecycle, creation dates, expiration countdowns, and DNSSEC signatures.
                    </div>
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800">
                      <strong>• BGP Autonomous System (ASN):</strong> Maps public IP addresses to ASN routing announcements and physical hosting locations.
                    </div>
                  </div>
                </div>
              </div>

              {/* Step 3 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  03
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Evaluate the Executive Posture Index & Exposure Dimensions</span>
                    <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">Posture Score</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Review Section 1 of the Unified Report. The composite <strong>Posture Score (0-100)</strong> and letter grade (A+ down to F) reflect cumulative exposure penalties calculated across four independent security dimensions:
                  </p>
                  <div className="flex flex-wrap gap-2 pt-1 text-[11px]">
                    <span className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono">
                      <strong>Network & Perimeter (25%):</strong> DNS health & attack surface breadth
                    </span>
                    <span className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono">
                      <strong>SSL/TLS Transport (25%):</strong> Cipher strength, certificate validity, HSTS
                    </span>
                    <span className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono">
                      <strong>Email Authentication (25%):</strong> DMARC policy enforcement, SPF, MX
                    </span>
                    <span className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono">
                      <strong>Shadow IT & Hygiene (25%):</strong> CNAME takeover risk, banner leaks
                    </span>
                  </div>
                </div>
              </div>

              {/* Step 4 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  04
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Triage Findings by Severity & Extract Remediation CLI Commands</span>
                    <span className="text-[11px] font-mono text-red-600 dark:text-red-400 font-semibold">Remediation</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Navigate to Section 2 (Vulnerability & Exposure Findings). Filter by <strong>CRITICAL</strong> and <strong>HIGH</strong>. 
                    Every finding includes exact technical evidence (such as the verbatim DNS response or leaked HTTP header), CWE and CVSS classifications, and an actionable remediation box with copy-paste terminal commands or web server configuration snippets (Nginx, Apache, Cloudflare, AWS Route53).
                  </p>
                </div>
              </div>

              {/* Step 5 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  05
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Execute Formal Regulatory Compliance Audits (NIST, CIS, ISO, PCI-DSS)</span>
                    <span className="text-[11px] font-mono text-purple-600 dark:text-purple-400 font-semibold">Audit Ready</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Inspect Section 6 (Regulatory Compliance). SurfaceTrace translates raw perimeter telemetry directly into control checks for <strong>NIST SP 800-53 Rev. 5</strong>, <strong>NIST CSF v2.0</strong>, <strong>CIS Controls v8</strong>, <strong>ISO/IEC 27001:2022</strong>, and <strong>PCI-DSS v4.0</strong>. 
                    Click <strong>"Copy Compliance Report (Markdown)"</strong> to generate an executive-ready brief with statutory citations for your audit binder or compliance ticketing system.
                  </p>
                </div>
              </div>

              {/* Step 6 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  06
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Map Exposures to Adversary Tactics via MITRE ATT&CK® v14</span>
                    <span className="text-[11px] font-mono text-amber-600 dark:text-amber-400 font-semibold">Threat Modeling</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Review Section 4 (MITRE ATT&CK Matrix). Understand how adversaries weaponize your specific perimeter weaknesses across 
                    <strong>Reconnaissance (TA0043)</strong>, <strong>Resource Development (TA0042)</strong>, and <strong>Initial Access (TA0001)</strong>. 
                    SurfaceTrace demonstrates how an attacker bridges a weak DMARC policy (T1566.002) or dangling CNAME (T1584.001) into corporate intrusion.
                  </p>
                </div>
              </div>

              {/* Step 7 */}
              <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800">
                <div className="w-8 h-8 rounded-lg bg-blue-600 text-white font-mono font-bold flex items-center justify-center shrink-0 text-sm shadow-xs">
                  07
                </div>
                <div className="space-y-2 flex-1">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center justify-between">
                    <span>Perform In-Browser Forensic SQL Queries in SQLite Audit Vault</span>
                    <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">Zero-Trust SQL</span>
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Click the <strong>SQLite Audit Vault</strong> tab in the navigation bar. 
                    Every scan result, raw HTTP header, certificate record, and outbound network log is committed into a client-side WebAssembly SQLite database. 
                    Run custom SQL statements (e.g., <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded font-mono">SELECT * FROM subdomains WHERE is_wildcard = 1;</code>) 
                    and download the immutable <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded font-mono">.sqlite</code> binary database for legal or compliance evidence preservation.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* PART 2: REAL-WORLD TARGET COMPANY CASE STUDY */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs space-y-6 transition-colors">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                    REALISTIC INDUSTRY CASE STUDY
                  </span>
                </div>
                <h3 className="text-lg sm:text-xl font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                  <span>Target Case Study: "ApexPay Global" (Fintech Corp Assessment)</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  How a Lead Security Architect leveraged SurfaceTrace to identify critical perimeter vulnerabilities prior to a PCI-DSS audit
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 text-xs font-mono shrink-0">
                <div>Target: <strong className="text-slate-800 dark:text-slate-200">apexpay.io</strong></div>
                <div className="text-slate-400 text-[10px]">Cloud: AWS • Cloudflare • Google</div>
              </div>
            </div>

            {/* Target Profile Card */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-[10px] uppercase tracking-wider font-bold text-slate-400 block font-sans">
                  The Organization
                </span>
                <p className="text-xs font-bold text-slate-900 dark:text-white">
                  ApexPay Global Inc. (Series C FinTech)
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Processes commercial credit card clearing and API payment payouts for 12,000 online merchants.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-[10px] uppercase tracking-wider font-bold text-slate-400 block font-sans">
                  The Practitioner Persona
                </span>
                <p className="text-xs font-bold text-slate-900 dark:text-white">
                  Marcus Vance, Lead AppSec & Compliance Architect
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Tasked with completing an independent external perimeter audit prior to annual PCI-DSS v4.0 QSA sign-off.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-[10px] uppercase tracking-wider font-bold text-slate-400 block font-sans">
                  The Compliance Mandate
                </span>
                <p className="text-xs font-bold text-slate-900 dark:text-white">
                  PCI-DSS v4.0, SOC 2 Type II, NIST SP 800-53
                </p>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Federal banking partner SLA requires 0 high-risk external perimeter vulnerabilities.
                </p>
              </div>
            </div>

            {/* End-to-End Walkthrough Scenario Narrative */}
            <div className="space-y-4 pt-2">
              <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Target className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>The End-to-End Assessment Execution:</span>
              </h4>

              {/* Scenario Step 1 */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 flex items-center justify-center text-[11px] font-bold">1</span>
                    Discovery: Uncovering Shadow Staging & Abandoned Hostnames
                  </span>
                  <span className="font-mono text-[10px] text-slate-400">Time: 00:03s</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  Marcus enters <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded">apexpay.io</code> into the scanner. SurfaceTrace's passive crt.sh and DNS pipeline immediately catalogs <strong>48 subdomains</strong>. 
                  Among standard production hosts, SurfaceTrace flags several forgotten legacy assets that never appeared in the company's internal IT asset inventory:
                  <code className="font-mono text-[11px] text-blue-600 dark:text-blue-400 ml-1">dev-portal.apexpay.io</code>, 
                  <code className="font-mono text-[11px] text-blue-600 dark:text-blue-400 ml-1">vpn-legacy.apexpay.io</code>, and 
                  <code className="font-mono text-[11px] text-blue-600 dark:text-blue-400 ml-1">docs.apexpay.io</code>.
                </p>
              </div>

              {/* Scenario Step 2 */}
              <div className="p-4 rounded-xl border border-red-200 dark:border-red-900/60 bg-red-50/30 dark:bg-red-950/20 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-red-900 dark:text-red-200 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400" />
                    Finding #1 (CRITICAL): Dangling CNAME Subdomain Takeover on docs.apexpay.io
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 font-bold">MITRE T1584.001</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  <strong>The Telemetry Discovery:</strong> SurfaceTrace alerts Marcus that <code className="font-mono bg-red-100/80 dark:bg-red-900/40 px-1 py-0.5 rounded">docs.apexpay.io</code> points to an AWS S3 bucket: 
                  <code className="font-mono text-[11px] ml-1">apexpay-documentation.s3-website-us-east-1.amazonaws.com</code>. 
                  Authoritative DoH resolution indicates the S3 bucket returns <code className="font-mono text-red-600 dark:text-red-400 font-bold">NXDOMAIN / NoSuchBucket</code>. 
                  Six months prior, an intern had deleted the S3 bucket during a documentation migration to Notion, but never removed the DNS CNAME record!
                </p>
                <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-red-200 dark:border-red-900/40 space-y-1 text-xs">
                  <div className="text-red-700 dark:text-red-400 font-bold flex items-center gap-1.5">
                    <Flame className="w-3.5 h-3.5" />
                    <span>Adversary Exploitation Weaponization Path:</span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                    Any threat actor could create an AWS account, allocate an S3 bucket named <code className="font-mono">apexpay-documentation</code> in <code className="font-mono">us-east-1</code> for $0.00, and instantly control all content served on <code className="font-mono">docs.apexpay.io</code>. 
                    They could harvest corporate session cookies (via SameSite lax scoping), inject malicious JavaScript, or phish API tokens from merchant developers under the legitimate company domain.
                  </p>
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  <strong>Marcus's Immediate Action:</strong> Marcus copies the remediation syntax provided in SurfaceTrace, opens AWS Route53, and permanently purges the orphaned CNAME record within 60 seconds.
                </div>
              </div>

              {/* Scenario Step 3 */}
              <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/30 dark:bg-amber-950/20 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-amber-900 dark:text-amber-200 flex items-center gap-2">
                    <Mail className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                    Finding #2 (HIGH): Unenforced DMARC Anti-Spoofing Policy (p=none)
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 font-bold">NIST SI-8 • CIS 9.5</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  <strong>The Telemetry Discovery:</strong> SurfaceTrace evaluates <code className="font-mono bg-amber-100/80 dark:bg-amber-900/40 px-1 py-0.5 rounded">_dmarc.apexpay.io</code>. 
                  The TXT record exists, but its policy tag is configured as <code className="font-mono text-amber-700 dark:text-amber-300 font-bold">p=none</code> (monitoring only).
                </p>
                <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-900/40 space-y-1 text-xs">
                  <div className="text-amber-700 dark:text-amber-400 font-bold flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5" />
                    <span>Business Email Compromise (BEC) Exposure:</span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                    With <code className="font-mono">p=none</code>, receiving mail gateways (Google Workspace, Microsoft 365) will NOT reject spoofed emails. 
                    An adversary can send an email with the header <code className="font-mono">From: "ApexPay Treasury" &lt;billing@apexpay.io&gt;</code> requesting partners update payout bank account numbers, achieving 100% inbox delivery.
                  </p>
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  <strong>Marcus's Immediate Action:</strong> SurfaceTrace supplies the exact DNS TXT record string to upgrade the policy to strict enforcement:
                  <code className="block font-mono text-[11px] bg-slate-100 dark:bg-slate-800 p-2 rounded mt-1.5 text-slate-800 dark:text-slate-200">
                    v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@apexpay.io; ruf=mailto:dmarc-forensics@apexpay.io;
                  </code>
                </div>
              </div>

              {/* Scenario Step 4 */}
              <div className="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/30 dark:bg-blue-950/20 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-blue-900 dark:text-blue-200 flex items-center gap-2">
                    <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    Finding #3 (MEDIUM): Missing HSTS Header & Cleartext HTTP Downgrade
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-bold">NIST SC-8 • CIS 9.2</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  <strong>The Telemetry Discovery:</strong> Inspection of HTTP perimeter response headers reveals that while HTTPS is supported, the web server does not broadcast a <code className="font-mono bg-blue-100/80 dark:bg-blue-900/40 px-1 py-0.5 rounded">Strict-Transport-Security</code> header. 
                  This permits protocol downgrade attacks (SSL Stripping) where an attacker on an insecure Wi-Fi network can intercept unencrypted HTTP credentials.
                </p>
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  <strong>Marcus's Immediate Action:</strong> Marcus adds the Cloudflare Transform Rule to attach:
                  <code className="block font-mono text-[11px] bg-slate-100 dark:bg-slate-800 p-2 rounded mt-1.5 text-slate-800 dark:text-slate-200">
                    Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
                  </code>
                </div>
              </div>

              {/* Scenario Step 5 */}
              <div className="p-4 rounded-xl border border-purple-200 dark:border-purple-900/60 bg-purple-50/30 dark:bg-purple-950/20 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-purple-900 dark:text-purple-200 flex items-center gap-2">
                    <Scale className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                    Phase 3: Formal Regulatory Audit Sign-off & SQLite Preservation
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold">Audit Sign-off</span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  Marcus switches to <strong>Section 6 (Regulatory Compliance Audit)</strong>. Prior to fixing the findings, ApexPay's compliance index was <strong>61/100 (HIGH RISK FAIL)</strong> due to failures under PCI-DSS Requirement 6.4.3 and NIST SP 800-53 SC-8.
                </p>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  After applying the remediation snippets, Marcus re-runs the scan:
                </p>
                <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-purple-200 dark:border-purple-900/40 text-xs space-y-1.5">
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-emerald-600 dark:text-emerald-400">✓ New Overall Compliance Score:</span>
                    <span className="font-extrabold text-sm text-slate-900 dark:text-white">96 / 100 (AUDIT RATING: PASS)</span>
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    NIST SP 800-53: 100% • NIST CSF: 95% • CIS v8: 100% • ISO 27001: 95% • PCI-DSS: 90%
                  </div>
                </div>
                <div className="text-xs text-slate-600 dark:text-slate-300">
                  Marcus clicks <strong>"Copy Compliance Report (Markdown)"</strong> to generate the executive report for the PCI Qualified Security Assessor (QSA), then switches to the <strong>SQLite Audit Vault</strong> and exports <code className="font-mono">apexpay_audit_2026.sqlite</code> as immutable cryptographic proof of due diligence.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: LEGAL CONFIRMATION & EXACT NETWORK QUERIES */}
      {activeSection === 'legal-queries' && (
        <div className="space-y-6 animate-in fade-in-50">
          {/* Legal Repercussions Analysis */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 sm:p-8 shadow-xs space-y-5 transition-colors">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                <Scale className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white">
                  Legal Assessment & Safe Harbor Confirmation
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Definitive legal review under the CFAA, US Judicial Precedent, and International Cyber Statutes
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-emerald-50/70 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/80 space-y-2">
              <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300 font-bold text-sm">
                <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                <span>Zero Legal Repercussions: Operating SurfaceTrace is 100% Lawful</span>
              </div>
              <p className="text-xs text-emerald-900 dark:text-emerald-200 leading-relaxed">
                Entering a domain into SurfaceTrace carries <strong>zero legal liability or criminal/civil repercussions</strong>. 
                SurfaceTrace performs exclusively <em>passive OSINT and standard web client retrieval</em>. It does not penetrate systems, does not bypass authentication, and does not conduct invasive port scans or stress testing.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <h4 className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  U.S. Supreme Court: Van Buren v. United States (2021)
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  In <em>Van Buren v. United States</em> (141 S. Ct. 1643), the Supreme Court explicitly curtailed the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030). The Court established that accessing publicly accessible data or systems without bypassing technological authentication gates (such as password credentials or token challenges) does <strong>not</strong> constitute unauthorized access or &quot;exceeding authorized access&quot;.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <h4 className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  U.S. 9th Circuit Court of Appeals: hiQ v. LinkedIn (2022)
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  In <em>hiQ Labs, Inc. v. LinkedIn Corp.</em> (31 F.4th 1180), the Ninth Circuit ruled that querying, aggregating, and analyzing publicly available internet data does not violate the CFAA or state common law trespass to chattels. Where data is public without an account wall, requesting that data is completely lawful.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <h4 className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Passive Third-Party Intermediaries (&gt;95% of queries)
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  Over 95% of the data collected by SurfaceTrace <strong>never touches the target domain&apos;s servers</strong>. SurfaceTrace queries public recursive caches (Cloudflare 1.1.1.1, Google 8.8.8.8), public Certificate Authorities (Sectigo crt.sh), and ICANN RDAP registries. The target has zero visibility of these queries.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <h4 className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Standard HTTP Client Request (The Sole Direct Query)
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  The only network packet sent directly to the target server is a single standard HTTPS GET request on port 443 with an 8-second timeout. This is identical in every respect to a user typing <code className="font-mono text-blue-600">https://example.com</code> into Chrome or Safari. It does not trigger firewall alerts, IDS alerts, or rate limits.
                </p>
              </div>
            </div>

            {/* Explicit What We Never Do Checklist */}
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Guaranteed Non-Intrusive Principles (What SurfaceTrace Never Does)
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 text-xs text-slate-600 dark:text-slate-300">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No port scanning (no SYN/TCP sweeps)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No SQL injection / XSS payloads</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No credential / dictionary spraying</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No directory or URL fuzzing (gobuster/ffuf)</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No denial-of-service / volumetric traffic</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No bypass of firewalls or access controls</span>
                </div>
              </div>
            </div>
          </div>

          {/* Exact Network Queries Specification Table */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 sm:p-8 shadow-xs space-y-4 transition-colors">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  <span>Itemized Outbound Network Queries Specification</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  The exact sequence of 8 deterministic HTTP/TLS requests dispatched by the server when any domain is entered
                </p>
              </div>
              <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold self-start sm:self-auto">
                Audited in server/scanner.ts
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-slate-600 dark:text-slate-400 font-semibold font-mono">
                    <th className="p-3">#</th>
                    <th className="p-3">Protocol / Query Type</th>
                    <th className="p-3">Destination Host</th>
                    <th className="p-3">Endpoint / Resource</th>
                    <th className="p-3">Target Contact?</th>
                    <th className="p-3">Telemetry Extracted</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">01</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      DNS-over-HTTPS (RFC 8484)
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      cloudflare-dns.com (1.1.1.1)
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /dns-query?name=&#123;domain&#125;&amp;type=&#123;A,AAAA,MX,TXT,NS,SOA,CAA&#125;
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Cache)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Public DNS zone records, IPv4/IPv6 apex addresses, mail servers (MX), and SPF directives
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">02</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      DMARC Policy DoH (RFC 8484)
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      dns.google (8.8.8.8)
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /resolve?name=_dmarc.&#123;domain&#125;&amp;type=TXT
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Cache)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Root DMARC policy (p=reject, p=quarantine, p=none), percentage enforcement, and forensic reports
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">03</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      Certificate Transparency Search (RFC 6962)
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      crt.sh (Sectigo Mirror)
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /?q=%.&#123;domain&#125;&amp;output=json
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Public CT)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Complete historical and active TLS/SSL certificate issuances, Subject Alternative Names (SANs), and subdomains
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">04</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      RDAP Domain Registration (RFC 7480-7484)
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      rdap.org (ICANN Accredited)
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /domain/&#123;domain&#125;
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Registry)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Registrar organization, registration creation date, expiration countdown, domain status locks
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">05</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      BGP &amp; ASN Routing Correlation
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      ip-api.com / BGPView
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /json/&#123;primaryIp&#125;
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Routing DB)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Autonomous System Number (ASN), network owner organization (e.g. AWS, Cloudflare, Azure), and IP geolocation
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">06</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      Subdomain Live Verification DoH
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      cloudflare-dns.com
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /dns-query?name=&#123;subdomain&#125;&amp;type=A
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Cache)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Determines if discovered hostnames actively resolve to a routable IP address or are dead/dormant
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="p-3 font-mono font-bold text-blue-600">07</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      Dangling CNAME Takeover Check
                    </td>
                    <td className="p-3 font-mono text-slate-600 dark:text-slate-300">
                      cloudflare-dns.com
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET /dns-query?name=&#123;subdomain&#125;&amp;type=CNAME
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 font-mono font-bold text-[10px]">
                        NO (Cache)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Detects orphaned pointers to third-party cloud buckets (AWS S3, GitHub Pages, Azure, Heroku)
                    </td>
                  </tr>

                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50 bg-blue-50/40 dark:bg-blue-950/20">
                    <td className="p-3 font-mono font-bold text-blue-600">08</td>
                    <td className="p-3 font-medium text-slate-900 dark:text-white">
                      Perimeter HTTP/TLS Header Probe
                    </td>
                    <td className="p-3 font-mono text-blue-700 dark:text-blue-300 font-bold">
                      Target Apex Server (Port 443)
                    </td>
                    <td className="p-3 font-mono text-[11px] text-slate-600 dark:text-slate-400">
                      GET https://&#123;domain&#125;/
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/60 text-blue-800 dark:text-blue-200 font-mono font-bold text-[10px]">
                        YES (Standard GET)
                      </span>
                    </td>
                    <td className="p-3 text-slate-600 dark:text-slate-300">
                      Standard TLS handshake (inspects certificate expiry) and reads response headers: HSTS, CSP, X-Frame-Options, Cookie Secure/HttpOnly flags
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400">
              <strong className="text-slate-800 dark:text-slate-200">Total Network Footprint:</strong> Exactly 8 benign, read-only requests. 7 of the 8 queries query third-party recursive resolvers or public logs. The 1 direct query to the target apex is identical to a standard user browsing to the homepage in an ordinary web browser.
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: WHAT IS EASM? */}
      {activeSection === 'overview' && (
        <div className="space-y-6 animate-in fade-in-50">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-3">
              <div className="w-10 h-10 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">The Perimeter Blindspot Problem</h3>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                Traditional cybersecurity relies heavily on internal vulnerability scanners (Nessus, Qualys, CrowdStrike agents) that require prior knowledge of asset IP addresses. 
                Modern organizations suffer from decentralized cloud adoption, multi-cloud sprawl, marketing microsites, staging subdomains, and ephemeral Kubernetes clusters. 
                Adversaries do not scan what security teams know about; they target the forgotten, unmonitored assets exposed on the public internet.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-3">
              <div className="w-10 h-10 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Eye className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">The Outside-In EASM Paradigm</h3>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                External Attack Surface Management takes the exact same perspective as an initial access broker or nation-state threat actor. 
                By starting with nothing more than an apex domain (e.g. <code className="text-blue-600 dark:text-blue-400 font-mono">company.com</code>), 
                SurfaceTrace discovers every exposed asset without deploying agents or firing intrusive port-scans that trigger perimeter firewalls.
              </p>
            </div>
          </div>

          {/* Contrast Table: Traditional vs EASM */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <span>Comparative Paradigm: Traditional Scanners vs. SurfaceTrace EASM</span>
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-slate-600 dark:text-slate-400 font-semibold font-mono">
                    <th className="p-3">Evaluation Metric</th>
                    <th className="p-3">Traditional Vulnerability Scanning</th>
                    <th className="p-3 text-blue-600 dark:text-blue-400">SurfaceTrace EASM Approach</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-slate-600 dark:text-slate-300">
                  <tr>
                    <td className="p-3 font-semibold text-slate-900 dark:text-white">Perspective</td>
                    <td className="p-3">Inside-out (Requires IP ranges, credentials, or installed agents)</td>
                    <td className="p-3 text-blue-600 dark:text-blue-400 font-medium">Outside-in (Adversary reconnaissance view, zero-knowledge)</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-slate-900 dark:text-white">Network Impact</td>
                    <td className="p-3">Active, invasive packet generation; can trigger IPS or cause service instability</td>
                    <td className="p-3 text-blue-600 dark:text-blue-400 font-medium">100% passive; queries public CT logs, public DoH caches, and standard HTTPS headers</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-slate-900 dark:text-white">Shadow IT Discovery</td>
                    <td className="p-3">Fails to discover assets outside specified IP subnets</td>
                    <td className="p-3 text-blue-600 dark:text-blue-400 font-medium">Continuously identifies uninventoried SaaS apps, staging clusters, and dev portals</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-slate-900 dark:text-white">Email & Transport Hygiene</td>
                    <td className="p-3">Typically ignored; focuses on software CVEs</td>
                    <td className="p-3 text-blue-600 dark:text-blue-400 font-medium">Audits DMARC enforcement, SPF syntax, CAA records, and HSTS preload policies</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 3: CORE CAPABILITIES & SQLITE */}
      {activeSection === 'capabilities' && (
        <div className="space-y-6 animate-in fade-in-50">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-3">
              <div className="w-9 h-9 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Globe className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-sm text-slate-900 dark:text-white">Subdomain & Asset Enumeration</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                Aggregates Subject Alternative Names from Certificate Transparency ledgers (crt.sh) and verifies live hosts via Cloudflare RFC 8484 DoH.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                <Database className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-sm text-slate-900 dark:text-white">Client-Side SQLite Audit Vault</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                All scans, findings, and network telemetry are indexed in an in-browser SQLite database (WASM + IndexedDB). Run live SQL queries and export to .sqlite or JSON.
              </p>
            </div>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-3">
              <div className="w-9 h-9 rounded-lg bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800 text-purple-600 dark:text-purple-400 flex items-center justify-center">
                <Sparkles className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-sm text-slate-900 dark:text-white">AI Adversary Simulation</h4>
              <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                Gemini 2.5 synthesizes discovered vulnerabilities into a realistic red-team initial access scenario mapped to CIS Controls v8.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 4: TECHNICAL PIPELINE */}
      {activeSection === 'pipeline' && (
        <div className="space-y-6 animate-in fade-in-50">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4">
            <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <span>How SurfaceTrace Collects Data (The 6-Stage Passive Engine)</span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              SurfaceTrace is strictly engineered to perform passive reconnaissance. All data is gathered through public mirrors, cryptographically verified transparency ledgers, and privacy-preserving DNS-over-HTTPS queries.
            </p>

            <div className="space-y-4 pt-2">
              {[
                {
                  step: '01',
                  name: 'Certificate Transparency Log Scraping',
                  tech: 'crt.sh JSON Mirror API & RFC 6962',
                  desc: 'Every SSL/TLS certificate issued by any recognized Certificate Authority is logged to immutable public ledgers. SurfaceTrace queries crt.sh for %.<domain> to harvest all valid and expired Subject Alternative Names.'
                },
                {
                  step: '02',
                  name: 'DNS-over-HTTPS (DoH) Multi-Record Resolution',
                  tech: 'Cloudflare 1.1.1.1 & Google 8.8.8.8 RFC 8484 Endpoints',
                  desc: 'Queries high-performance DoH nameservers concurrently for A, AAAA, CNAME, MX, TXT, NS, and SOA records without exposing queries to internal network sniffers.'
                },
                {
                  step: '03',
                  name: 'Dangling CNAME Provider Pattern Matching',
                  tech: 'Automated Heuristic Matching against 8+ Cloud Signatures',
                  desc: 'Each identified CNAME target is compared against known hosted provider patterns (s3.amazonaws.com, github.io, azurewebsites.net, herokudns.com). If the CNAME target is unresolved or orphaned, a critical Subdomain Takeover finding is recorded.'
                },
                {
                  step: '04',
                  name: 'Email Defense & Policy Evaluation Engine',
                  tech: 'RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)',
                  desc: 'Parses TXT records for SPF mechanisms and validates the root _dmarc.<domain> policy. Flags p=none as an initial access spoofing vulnerability.'
                },
                {
                  step: '05',
                  name: 'Transport & Security Header Inspection',
                  tech: 'TLS/HTTPS Handshake & HTTP/2 Header Parsing',
                  desc: 'Initiates a standard client-side TLS handshake to inspect HTTP response headers. Assesses HSTS max-age thresholds, CSP directives, and flags verbose Server banners.'
                },
                {
                  step: '06',
                  name: 'BGP Routing & Autonomous System Number (ASN) Lookup',
                  tech: 'BGPView REST API & IPinfo Geo-Routing Datasets',
                  desc: 'Translates discovered IP addresses into announced BGP Autonomous System Numbers (ASNs), network owner names, CIDR prefixes, and hosting provider classifications.'
                }
              ].map((pipe) => (
                <div key={pipe.step} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-1.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center gap-2">
                      <span className="w-6 h-6 rounded-md bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 flex items-center justify-center font-mono font-bold text-blue-700 dark:text-blue-400 text-xs">
                        {pipe.step}
                      </span>
                      <h4 className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">{pipe.name}</h4>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{pipe.tech}</span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 font-sans pl-8 leading-relaxed">
                    {pipe.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 5: CURATED OSINT DIRECTORY */}
      {activeSection === 'osint-dir' && (
        <div className="space-y-6 animate-in fade-in-50">
          <OsintDirectoryTab currentDomain={currentDomain} />
        </div>
      )}

      {/* SECTION 6: MITRE ATT&CK FRAMEWORK */}
      {activeSection === 'mitre' && (
        <div className="space-y-6 animate-in fade-in-50">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4">
            <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              <span>Mapping External Surface to the MITRE ATT&CK® Enterprise Matrix</span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              SurfaceTrace does not treat security findings in isolation. It maps every digital footprint artifact and OSINT source directly to the 
              <strong> MITRE ATT&CK v14</strong> framework, allowing SOC analysts, threat hunters, and CISOs to prioritize defenses based on how real adversaries operate.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-blue-600 dark:text-blue-400">TA0043: Reconnaissance</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-mono">Pre-Attack</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Techniques used by adversaries to actively or passively gather information that can be used to support targeting (T1596: Search Open Technical Databases, T1590: Gather Victim Network Info).
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-red-600 dark:text-red-400">TA0001: Initial Access</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 font-mono">Infiltration</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Techniques used to gain an initial foothold on the corporate network (T1190: Exploit Public-Facing Application, T1566: Phishing via spoofed email without DMARC enforcement).
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION: NIST & Regulatory Compliance Mapping */}
      {activeSection === 'compliance' && (
        <div className="space-y-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs space-y-5">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Scale className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                  <span>Regulatory Compliance & External Control Validation</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  How passive external attack surface signals translate directly into formal compliance audit baselines
                </p>
              </div>

              <button
                onClick={() => onNavigateTab('overview')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-50 hover:bg-purple-100 dark:bg-purple-950/60 dark:hover:bg-purple-900/60 text-purple-700 dark:text-purple-300 text-xs font-semibold border border-purple-200 dark:border-purple-800 transition-colors cursor-pointer"
              >
                <span>View Live Scan Compliance Report</span>
              </button>
            </div>

            <div className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed space-y-3">
              <p>
                Compliance audits (such as NIST SP 800-53, FedRAMP, SOC 2, and PCI-DSS) evaluate whether mandated security controls are actively enforced. <strong>External Attack Surface Management (EASM) provides irrefutable empirical evidence</strong> of boundary control health because an auditor or attacker sees the exact same perimeter defenses.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-purple-600 dark:text-purple-400">NIST SP 800-53 Rev. 5</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-mono">Federal Baseline</span>
                </div>
                <ul className="text-xs text-slate-600 dark:text-slate-300 space-y-1.5 pt-1">
                  <li><strong>SC-8 / SC-8(1):</strong> Strict TLS encryption in transit & HSTS header validation.</li>
                  <li><strong>SI-8 / SI-8(2):</strong> Email sender authentication (DMARC p=reject, SPF -all).</li>
                  <li><strong>SC-7(10):</strong> Boundary protection suppressing web server banners and version leaks.</li>
                  <li><strong>CM-8:</strong> External asset inventory & elimination of dangling CNAME takeovers.</li>
                  <li><strong>SC-12 / SC-17:</strong> PKI certificate expiry & cryptography lifecycle hygiene.</li>
                </ul>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-blue-600 dark:text-blue-400">NIST CSF v2.0 & CIS v8</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-mono">Industry Benchmarks</span>
                </div>
                <ul className="text-xs text-slate-600 dark:text-slate-300 space-y-1.5 pt-1">
                  <li><strong>NIST PR.DS-02:</strong> Cryptographic protection of public data in transit.</li>
                  <li><strong>NIST PR.IR-01:</strong> Perimeter infrastructure defense (CSP, XFO, XCTO).</li>
                  <li><strong>NIST ID.AM-02:</strong> External digital surface cataloging across ASNs and subdomains.</li>
                  <li><strong>CIS Control 9.2:</strong> Exclusive enforcement of modern TLS protocols & ciphers.</li>
                  <li><strong>CIS Control 9.5:</strong> Implementation of DMARC with sender enforcement.</li>
                </ul>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400">PCI-DSS v4.0 & ISO 27001</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-mono">Commercial Standards</span>
                </div>
                <ul className="text-xs text-slate-600 dark:text-slate-300 space-y-1.5 pt-1">
                  <li><strong>PCI-DSS Req 6.4.3:</strong> Client-side script protection and framing defense (CSP & XFO).</li>
                  <li><strong>PCI-DSS Req 8.2.2:</strong> Secure and HttpOnly cookie transmission controls.</li>
                  <li><strong>ISO 27001 A.8.20:</strong> Perimeter network security & DNS record governance.</li>
                  <li><strong>ISO 27001 A.8.24:</strong> Cryptographic control enforcement on external boundaries.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
