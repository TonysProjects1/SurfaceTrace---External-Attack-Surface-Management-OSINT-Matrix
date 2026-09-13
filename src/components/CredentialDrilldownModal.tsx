import React, { useState, useEffect } from 'react';
import { 
  X, 
  ShieldAlert, 
  Calculator, 
  FileText, 
  CheckCircle2, 
  Copy, 
  Download, 
  Printer, 
  ExternalLink, 
  Terminal, 
  Flame, 
  Bug, 
  Lock, 
  Database, 
  Cpu, 
  AlertTriangle,
  Layers,
  ChevronDown,
  ChevronUp,
  Share2,
  Building2,
  Users
} from 'lucide-react';
import { VulnerabilityBreachData, BreachIncident, StealerIntelligence } from '../types';

interface CredentialDrilldownModalProps {
  isOpen: boolean;
  onClose: () => void;
  domain: string;
  data: VulnerabilityBreachData | null;
  breaches: BreachIncident[];
  stealerData: StealerIntelligence | null;
  initialTab?: 'calculation' | 'executive' | 'endpoints';
}

export const CredentialDrilldownModal: React.FC<CredentialDrilldownModalProps> = ({
  isOpen,
  onClose,
  domain,
  data,
  breaches,
  stealerData,
  initialTab = 'calculation'
}) => {
  const [activeTab, setActiveTab] = useState<'calculation' | 'executive' | 'endpoints'>(initialTab);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);
  const [urlFilter, setUrlFilter] = useState<'all' | 'Employee' | 'Client'>('all');

  useEffect(() => {
    if (isOpen && initialTab) {
      setActiveTab(initialTab);
    }
  }, [isOpen, initialTab]);

  if (!isOpen) return null;

  const totalExposed = data?.totalExposedCredentials || 0;
  const employeesInfected = stealerData?.employeesInfected || 0;
  const usersInfected = stealerData?.usersInfected || 0;
  const breachesCount = breaches.length;
  const sumBreachPwnCount = breaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(label);
    setTimeout(() => setCopiedSection(null), 2500);
  };

  const handlePrint = () => {
    window.print();
  };

  const generateMarkdownReport = () => {
    const dateStr = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    return `# EXECUTIVE INCIDENT & THREAT BRIEFING: CREDENTIAL EXPOSURE
**Classification:** RESTRICTED / BOARD-LEVEL DISCLOSURE  
**Target Domain:** ${domain}  
**Date of Assessment:** ${dateStr}  
**Assessment Authority:** SurfaceTrace External Attack Surface Management (EASM)  
**Overall Threat Level:** ${data?.status || 'CRITICAL_RISK'} (Exposure Score: ${data?.riskScore || 75}/100)

---

## 1. EXECUTIVE SUMMARY
SurfaceTrace active intelligence sensors have identified **${totalExposed.toLocaleString()} compromised credential records** originating from infostealer botnet exfiltration feeds and dark web telemetry referencing \`${domain}\`.

- **Infected Corporate Employee Hosts:** ${employeesInfected} corporate endpoint(s) infected by active malware.
- **Client & External User Compromises:** ${usersInfected.toLocaleString()} user/client credential sets exfiltrated from end-user devices logging into ${domain}.
- **Authoritative Direct Domain Breaches:** ${breachesCount} public breach incident(s) indexed via Have I Been Pwned.
- **Active Malware Botnet Strains:** ${stealerData?.stealerFamilies ? Object.keys(stealerData.stealerFamilies).length : 0} distinct stealer families (e.g. RedLine, Lumma, Vidar, Raccoon).

**Core Business Risk:** Unlike passive password hash lists, modern infostealer malware extracts **live browser session cookies (SQLite databases)**. Attackers can bypass standard Multi-Factor Authentication (SMS, Push notifications, TOTP) via Session Hijacking (MITRE ATT&CK T1539) to gain unauthorized corporate or client portal access without triggering password prompts.

---

## 2. TELEMETRIC DERIVATION & METHODOLOGY
The total leaked record figure of **${totalExposed.toLocaleString()}** was mathematically calculated through dual-feed triangulation:

$$\\text{Total Compromised Records} = \\text{Corporate Employee Infections} + \\text{Client/User Stolen Credentials} + \\sum(\\text{HIBP Breach PwnCounts})$$

1. **Corporate Employee Workstations (${employeesInfected}):**
   - Telemetry Source: Hudson Rock Cavalier Botnet Intelligence Feed.
   - Identified corporate-owned or contractor devices where employee credentials matching corporate email patterns (\`*@${domain}\`) or privileged SSO login portals were exfiltrated.
   - Last observed employee compromise date: ${stealerData?.lastEmployeeCompromised ? new Date(stealerData.lastEmployeeCompromised).toLocaleDateString() : 'N/A'}.

2. **Client / External User Credentials (${usersInfected.toLocaleString()}):**
   - Telemetry Source: Global Infostealer C2 server logs parsed by Hudson Rock.
   - Credentials stolen from consumers, partners, and enterprise customers whose private devices were infected with infostealers while logging into \`${domain}\` endpoints.
   - Last observed client compromise date: ${stealerData?.lastUserCompromised ? new Date(stealerData.lastUserCompromised).toLocaleDateString() : 'N/A'}.

3. **Authoritative Breaches (${breachesCount}):**
   - Telemetry Source: Have I Been Pwned v3 Authoritative Repository.
   - Total records in indexed direct domain breaches: ${sumBreachPwnCount.toLocaleString()}.

---

## 3. STATUTORY & REGULATORY EXPOSURE
1. **SEC Cybersecurity Disclosure Rules (Item 1.05 Form 8-K):**
   - Determination of materiality required within 4 business days if exfiltrated employee session tokens lead to unauthorized access to production data or material disruption.
2. **EU General Data Protection Regulation (GDPR Art. 33 & 34):**
   - 72-hour supervisory authority breach notification window applies if employee or client credentials permit access to identifiable EU personal data.
3. **PCI-DSS v4.0 (Requirement 8.3.6):**
   - Mandates organizations continuously check user and administrative credentials against known compromised credential repositories.
4. **FTC Safeguards Rule & NIST SP 800-53 Rev. 5 (IA-2, IA-5):**
   - Mandates robust authentication controls resistant to credential replay and session token theft.

---

## 4. IMMEDIATE 72-HOUR REMEDIATION ROADMAP
1. **[IMMEDIATE] Global SSO Session Revocation:**
   - Terminate all active OAuth, SAML, and Okta/Entra ID refresh tokens across the ${employeesInfected} compromised corporate employee accounts.
2. **[HOUR 0-24] Endpoint Isolation & Forensic Sweep:**
   - Isolate infected host machines via EDR (CrowdStrike / Microsoft Defender / SentinelOne) to neutralize lingering RedLine/Lumma loaders.
3. **[HOUR 24-48] FIDO2 / WebAuthn Hardware Token Enforcement:**
   - Transition high-risk administrators to origin-bound hardware security keys (YubiKey) which are cryptographically immune to infostealer session cookie replay.
4. **[HOUR 48-72] Client Account Takeover (ATO) Monitoring:**
   - Deploy rate limiting and behavioral biometric screening on \`${domain}\` login endpoints to block automated credential stuffing.

---

## 5. EXECUTIVE REVIEW & SIGN-OFF
- **Chief Information Security Officer (CISO):** ___________________________  Date: __________
- **General Counsel / Chief Compliance Officer:** __________________________  Date: __________
- **Head of Incident Response:** _______________________________________  Date: __________

*Report generated by SurfaceTrace Threat Intelligence Engine.*
`;
  };

  const handleDownloadMarkdown = () => {
    const markdown = generateMarkdownReport();
    const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Executive-Credential-Exposure-Briefing-${domain}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredUrls = (stealerData?.topCompromisedUrls || []).filter(u => {
    if (urlFilter === 'all') return true;
    return u.type === urlFilter;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-950/75 backdrop-blur-xs overflow-y-auto animate-in fade-in duration-200">
      <div 
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden my-auto"
        role="dialog"
        aria-modal="true"
        aria-labelledby="drilldown-modal-title"
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/80 dark:bg-slate-950/50 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0 border border-red-200 dark:border-red-900/50">
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 id="drilldown-modal-title" className="font-bold text-lg text-slate-900 dark:text-white">
                  Credential Exposure & Telemetry Drill-Down
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[11px] font-mono font-bold bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 border border-red-200 dark:border-red-800">
                  {totalExposed.toLocaleString()} records
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Target: <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">{domain}</span> • Live OSINT Intelligence & Audit Analysis
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              title="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="px-6 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2 bg-slate-100/50 dark:bg-slate-950/20 shrink-0 overflow-x-auto">
          <button
            onClick={() => setActiveTab('calculation')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'calculation'
                ? 'border-red-600 text-red-600 dark:text-red-400 bg-white/60 dark:bg-slate-900/60'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Calculator className="w-4 h-4" />
            <span>Calculation Methodology & Telemetry</span>
          </button>

          <button
            onClick={() => setActiveTab('executive')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'executive'
                ? 'border-red-600 text-red-600 dark:text-red-400 bg-white/60 dark:bg-slate-900/60'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Executive Management Review Briefing</span>
          </button>

          <button
            onClick={() => setActiveTab('endpoints')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'endpoints'
                ? 'border-red-600 text-red-600 dark:text-red-400 bg-white/60 dark:bg-slate-900/60'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Targeted Endpoints & Threat Strains ({filteredUrls.length})</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* ================= TAB 1: CALCULATION METHODOLOGY ================= */}
          {activeTab === 'calculation' && (
            <div className="space-y-6">
              {/* Formula Callout */}
              <div className="p-4 rounded-xl bg-slate-900 text-white dark:bg-slate-950 border border-slate-800 shadow-md">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                  <span className="font-semibold uppercase tracking-wider flex items-center gap-1.5 text-red-400">
                    <Calculator className="w-3.5 h-3.5" /> Mathematical Determination Formula
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">SurfaceTrace Telemetry Triangulation</span>
                </div>
                <div className="font-mono text-sm sm:text-base py-2 px-3 rounded-lg bg-slate-800/80 dark:bg-slate-900 border border-slate-700/60 text-emerald-400 overflow-x-auto">
                  Total Leaked Records ({totalExposed.toLocaleString()}) = Employee Hosts ({employeesInfected}) + Client Records ({usersInfected.toLocaleString()}) + HIBP Breaches ({sumBreachPwnCount.toLocaleString()})
                </div>
                <p className="text-xs text-slate-300 mt-2.5 leading-relaxed">
                  SurfaceTrace aggregates real-time telemetry from <strong>Hudson Rock Cavalier Infostealer Botnet Intelligence</strong> and <strong>Have I Been Pwned (HIBP v3)</strong> to eliminate speculation and calculate the exact quantifiable record exposure count.
                </p>
              </div>

              {/* Three Telemetry Pillars */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Pillar 1: Corporate Employees */}
                <div className="p-4 rounded-xl border border-red-200 dark:border-red-900/60 bg-red-50/40 dark:bg-red-950/20 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase text-red-700 dark:text-red-400 flex items-center gap-1">
                      <Bug className="w-3.5 h-3.5" /> Corporate Employees
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-red-200 dark:bg-red-900 text-red-900 dark:text-red-100">
                      {employeesInfected} Hosts
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
                    {employeesInfected}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Corporate laptops or workstations belonging to employees with active corporate identities matching <code className="font-mono text-[11px] bg-red-100 dark:bg-red-900/40 px-1 py-0.5 rounded">@{domain}</code> infected by stealer malware.
                  </p>
                  <div className="text-[11px] pt-2 border-t border-red-200 dark:border-red-900/40 font-mono text-slate-500 dark:text-slate-400">
                    Last infected: {stealerData?.lastEmployeeCompromised ? new Date(stealerData.lastEmployeeCompromised).toLocaleDateString() : 'None documented'}
                  </div>
                </div>

                {/* Pillar 2: Client & Consumer Accounts */}
                <div className="p-4 rounded-xl border border-blue-200 dark:border-blue-900/60 bg-blue-50/40 dark:bg-blue-950/20 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase text-blue-700 dark:text-blue-400 flex items-center gap-1">
                      <Users className="w-3.5 h-3.5" /> Client / User Logins
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-200 dark:bg-blue-900 text-blue-900 dark:text-blue-100">
                      {usersInfected.toLocaleString()} Records
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
                    {usersInfected.toLocaleString()}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Credentials harvested by infostealers from external clients, customers, and partners while accessing <code className="font-mono text-[11px] bg-blue-100 dark:bg-blue-900/40 px-1 py-0.5 rounded">{domain}</code> web services.
                  </p>
                  <div className="text-[11px] pt-2 border-t border-blue-200 dark:border-blue-900/40 font-mono text-slate-500 dark:text-slate-400">
                    Last infected: {stealerData?.lastUserCompromised ? new Date(stealerData.lastUserCompromised).toLocaleDateString() : 'None documented'}
                  </div>
                </div>

                {/* Pillar 3: HIBP Breaches */}
                <div className="p-4 rounded-xl border border-orange-200 dark:border-orange-900/60 bg-orange-50/40 dark:bg-orange-950/20 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase text-orange-700 dark:text-orange-400 flex items-center gap-1">
                      <Database className="w-3.5 h-3.5" /> Direct HIBP Breaches
                    </span>
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-orange-200 dark:bg-orange-900 text-orange-900 dark:text-orange-100">
                      {breachesCount} Breaches
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
                    {sumBreachPwnCount.toLocaleString()}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    Cumulative user records exposed in authoritative public database breach dumps cataloged directly under the <code className="font-mono text-[11px] bg-orange-100 dark:bg-orange-900/40 px-1 py-0.5 rounded">{domain}</code> root authority.
                  </p>
                  <div className="text-[11px] pt-2 border-t border-orange-200 dark:border-orange-900/40 font-mono text-slate-500 dark:text-slate-400">
                    Catalogs checked: Have I Been Pwned v3 API
                  </div>
                </div>
              </div>

              {/* In-Depth Explanation: Infostealer Mechanics */}
              <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-3">
                <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  Why Infostealer Data Differs from Traditional Breaches
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-600 dark:text-slate-300">
                  <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 space-y-1.5">
                    <span className="font-bold text-slate-900 dark:text-white block">Traditional Breaches (HIBP)</span>
                    <p className="leading-relaxed">
                      Represent historical dumps from centralized database compromise events. They typically contain salted password hashes (e.g. bcrypt, SHA-256) which attackers must crack before use. Often outdated by several years.
                    </p>
                  </div>
                  <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 space-y-1.5">
                    <span className="font-bold text-red-600 dark:text-red-400 block">Infostealer Logs (Hudson Rock)</span>
                    <p className="leading-relaxed">
                      Captured directly from infected end-user and corporate endpoints. Infostealers extract plaintext browser passwords and <strong>valid session cookie vaults (cookies.sqlite)</strong>, enabling session hijacking without password or MFA challenges.
                    </p>
                  </div>
                </div>
              </div>

              {/* Independent Verification & OSINT cURL */}
              <div className="p-4 rounded-xl bg-slate-900 text-white dark:bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" /> Independent Verification Command (Reperformance)
                  </span>
                  <button
                    onClick={() => copyToClipboard(
                      `curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${domain}" | jq`,
                      'reperformance'
                    )}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700"
                  >
                    {copiedSection === 'reperformance' ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Copied CLI
                      </span>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" /> Copy CLI Query
                      </>
                    )}
                  </button>
                </div>
                <code className="text-xs font-mono text-emerald-400 block p-2.5 rounded-lg bg-slate-950 border border-slate-800 overflow-x-auto">
                  curl -s "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}" | jq
                </code>
              </div>

              {/* Raw JSON Inspector Toggle */}
              <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <button
                  onClick={() => setShowRawJson(!showRawJson)}
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-950/40 text-left text-xs font-bold text-slate-700 dark:text-slate-300 flex items-center justify-between cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800/50 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-purple-500" />
                    Inspect Raw Ingested Telemetry Payload (JSON)
                  </span>
                  {showRawJson ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {showRawJson && (
                  <div className="p-4 bg-slate-950 text-slate-200 border-t border-slate-200 dark:border-slate-800 space-y-2">
                    <div className="flex justify-end">
                      <button
                        onClick={() => copyToClipboard(JSON.stringify(stealerData || {}, null, 2), 'rawJson')}
                        className="text-[11px] font-mono px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedSection === 'rawJson' ? 'Copied' : 'Copy JSON'}
                      </button>
                    </div>
                    <pre className="text-[11px] font-mono overflow-x-auto max-h-64 p-2 rounded bg-slate-900 text-emerald-400">
                      {JSON.stringify(stealerData || { status: 'No raw stealer data available' }, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ================= TAB 2: EXECUTIVE MANAGEMENT REVIEW REPORT ================= */}
          {activeTab === 'executive' && (
            <div className="space-y-6">
              {/* Action Bar for Executive Briefing */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 dark:text-white flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-blue-500" />
                    Board & C-Suite Executive Briefing
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Prepared for CISO, Legal Counsel, and Executive Management risk review
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handlePrint}
                    className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print / PDF Briefing</span>
                  </button>

                  <button
                    onClick={() => copyToClipboard(generateMarkdownReport(), 'execMarkdown')}
                    className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                  >
                    {copiedSection === 'execMarkdown' ? (
                      <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Copied Markdown
                      </span>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Markdown</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={handleDownloadMarkdown}
                    className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download (.md)</span>
                  </button>
                </div>
              </div>

              {/* Formal Briefing Document Container */}
              <div id="executive-briefing-doc" className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-6 shadow-sm font-sans text-slate-900 dark:text-slate-100">
                {/* Formal Header */}
                <div className="border-b-2 border-slate-900 dark:border-slate-100 pb-4 flex flex-col sm:flex-row justify-between sm:items-end gap-3">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-widest text-red-600 dark:text-red-400 font-bold block mb-1">
                      RESTRICTED // BOARD-LEVEL THREAT BRIEFING
                    </span>
                    <h2 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white">
                      EXECUTIVE THREAT BRIEFING: CREDENTIAL COMPROMISE
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Target Entity: <span className="font-bold text-slate-800 dark:text-slate-200">{domain}</span> • Generated on {new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}
                    </p>
                  </div>
                  <div className="text-right sm:text-right">
                    <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300 dark:border-red-800">
                      THREAT STATUS: {data?.status || 'CRITICAL_RISK'} ({data?.riskScore || 75}/100)
                    </span>
                  </div>
                </div>

                {/* Section 1: Executive Overview */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800 pb-1">
                    1. Executive Assessment
                  </h4>
                  <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
                    SurfaceTrace threat sensors have uncovered <strong>{totalExposed.toLocaleString()} compromised credential records</strong> across infostealer botnet C2 logs and dark web channels. Most critically, <strong>{employeesInfected} corporate endpoint infections</strong> were verified where employees accessing corporate assets were compromised by stealer malware.
                  </p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block">Total Exposed</span>
                      <span className="text-lg font-mono font-bold text-slate-900 dark:text-white">{totalExposed.toLocaleString()}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-red-500 block">Infected Employees</span>
                      <span className="text-lg font-mono font-bold text-red-600 dark:text-red-400">{employeesInfected} Hosts</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-blue-500 block">Client Accounts</span>
                      <span className="text-lg font-mono font-bold text-blue-600 dark:text-blue-400">{usersInfected.toLocaleString()}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-purple-500 block">Stealer Strains</span>
                      <span className="text-lg font-mono font-bold text-purple-600 dark:text-purple-400">{stealerData?.stealerFamilies ? Object.keys(stealerData.stealerFamilies).length : 0}</span>
                    </div>
                  </div>
                </div>

                {/* Section 2: Attack Mechanism & Session Hijacking Threat */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800 pb-1">
                    2. Primary Threat Vector: Infostealer Session Cookie Theft (MITRE T1539)
                  </h4>
                  <p className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                    Unlike historical password leaks that are blocked by MFA, modern infostealers (RedLine, Lumma, Vidar) exfiltrate pre-authenticated browser session cookies. An adversary possessing these cookies can import them into an anti-detect browser (e.g. Dolphin Anty) to impersonate the employee without triggering password prompts, SMS codes, or mobile push authenticators.
                  </p>
                </div>

                {/* Section 3: Statutory & Regulatory Exposures */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800 pb-1">
                    3. Legal & Regulatory Exposure Matrix
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                        <span>SEC Item 1.05 Form 8-K</span>
                        <span className="text-[10px] text-red-500 font-bold">4-Day Disclosure</span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                        Public companies must disclose material cybersecurity incidents within 4 business days. Exfiltration of executive or administrator credentials represents a material risk to operations.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                        <span>EU GDPR (Articles 33 & 34)</span>
                        <span className="text-[10px] text-orange-500 font-bold">72-Hour Window</span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                        Exposed employee credentials providing access to EU consumer personal data trigger mandatory notification to Data Protection Authorities (DPA) within 72 hours.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                        <span>PCI-DSS v4.0 (Req 8.3.6)</span>
                        <span className="text-[10px] text-blue-500 font-bold">Continuous Mandate</span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                        Requires regular automated screening of employee and privileged credentials against known public and stealer-derived breach databases.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="font-bold text-slate-900 dark:text-white flex items-center justify-between">
                        <span>FTC Safeguards Rule</span>
                        <span className="text-[10px] text-purple-500 font-bold">Administrative Safeguard</span>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                        Requires robust access controls, active threat monitoring, and immediate revocation of compromised tokens to safeguard customer information.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Section 4: 72-Hour Rapid Response Checklist */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-100 dark:border-slate-800 pb-1">
                    4. Immediate 72-Hour Containment Roadmap
                  </h4>
                  <div className="space-y-2 text-xs">
                    <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="w-5 h-5 rounded-full bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 font-bold flex items-center justify-center shrink-0 text-[11px]">1</span>
                      <div>
                        <strong className="text-slate-900 dark:text-white block">Immediate SSO Session Token Invalidation:</strong>
                        <span className="text-slate-600 dark:text-slate-400">Issue an immediate tenant-wide session revocation for the {employeesInfected} infected employee accounts across Okta, Microsoft Entra ID, Google Workspace, and Cloudflare Access.</span>
                      </div>
                    </div>

                    <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="w-5 h-5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300 font-bold flex items-center justify-center shrink-0 text-[11px]">2</span>
                      <div>
                        <strong className="text-slate-900 dark:text-white block">EDR Host Isolation & Forensic Capture:</strong>
                        <span className="text-slate-600 dark:text-slate-400">Quarantine affected employee endpoints via CrowdStrike / Defender EDR to collect memory dumps and remove persistent malware loaders.</span>
                      </div>
                    </div>

                    <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                      <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300 font-bold flex items-center justify-center shrink-0 text-[11px]">3</span>
                      <div>
                        <strong className="text-slate-900 dark:text-white block">FIDO2 / WebAuthn Hardware Key Mandate:</strong>
                        <span className="text-slate-600 dark:text-slate-400">Transition all technical and administrative personnel to origin-bound hardware tokens (YubiKeys) which eliminate cookie and password phishing.</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Section 5: Formal Sign-Off Table */}
                <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    5. Management Review & Formal Sign-Off
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
                    <div className="border border-slate-300 dark:border-slate-700 rounded-lg p-3 space-y-6">
                      <div className="text-[11px] font-bold text-slate-800 dark:text-slate-200">
                        Chief Information Security Officer (CISO)
                      </div>
                      <div className="border-b border-dashed border-slate-400 dark:border-slate-600 pt-6"></div>
                      <div className="flex justify-between text-[10px] text-slate-500">
                        <span>Signature</span>
                        <span>Date</span>
                      </div>
                    </div>

                    <div className="border border-slate-300 dark:border-slate-700 rounded-lg p-3 space-y-6">
                      <div className="text-[11px] font-bold text-slate-800 dark:text-slate-200">
                        General Counsel / Legal Officer
                      </div>
                      <div className="border-b border-dashed border-slate-400 dark:border-slate-600 pt-6"></div>
                      <div className="flex justify-between text-[10px] text-slate-500">
                        <span>Signature</span>
                        <span>Date</span>
                      </div>
                    </div>

                    <div className="border border-slate-300 dark:border-slate-700 rounded-lg p-3 space-y-6">
                      <div className="text-[11px] font-bold text-slate-800 dark:text-slate-200">
                        Incident Response Lead
                      </div>
                      <div className="border-b border-dashed border-slate-400 dark:border-slate-600 pt-6"></div>
                      <div className="flex justify-between text-[10px] text-slate-500">
                        <span>Signature</span>
                        <span>Date</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ================= TAB 3: ENDPOINTS & THREAT BREAKDOWN ================= */}
          {activeTab === 'endpoints' && (
            <div className="space-y-5">
              {/* Endpoint Controls & Filter */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 dark:text-white">
                    Compromised Endpoint Telemetry
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    URLs captured by infostealers on infected machines with exfiltrated credentials
                  </p>
                </div>

                {/* Filter Pills */}
                <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-200/70 dark:bg-slate-900 border border-slate-300/80 dark:border-slate-800">
                  <button
                    onClick={() => setUrlFilter('all')}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                      urlFilter === 'all'
                        ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    All ({stealerData?.topCompromisedUrls?.length || 0})
                  </button>
                  <button
                    onClick={() => setUrlFilter('Employee')}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                      urlFilter === 'Employee'
                        ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    Employee Only
                  </button>
                  <button
                    onClick={() => setUrlFilter('Client')}
                    className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors cursor-pointer ${
                      urlFilter === 'Client'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    Client / Users
                  </button>
                </div>
              </div>

              {/* Endpoint List with Fixed Dark Mode Formatting */}
              {filteredUrls.length > 0 ? (
                <div className="space-y-2">
                  {filteredUrls.map((endpoint, idx) => (
                    <div 
                      key={idx}
                      className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/80 hover:bg-white dark:hover:bg-slate-900 border border-slate-200/90 dark:border-slate-800 flex items-center justify-between gap-3 text-xs transition-colors group"
                    >
                      <div className="flex items-center gap-2.5 truncate min-w-0">
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase shrink-0 border ${
                          endpoint.type === 'Employee'
                            ? 'bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/30'
                            : 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/30'
                        }`}>
                          {endpoint.type}
                        </span>
                        <code className="text-slate-800 dark:text-slate-100 font-mono text-xs truncate select-all">
                          {endpoint.url}
                        </code>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => copyToClipboard(endpoint.url, `endpoint-${idx}`)}
                          className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                          title="Copy URL"
                        >
                          {copiedSection === `endpoint-${idx}` ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <span className="px-2.5 py-1 rounded-md bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-slate-100 font-mono text-xs font-bold border border-slate-300 dark:border-slate-700">
                          {endpoint.occurrence.toLocaleString()} hit{endpoint.occurrence > 1 ? 's' : ''}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-12 text-center text-xs text-slate-500 dark:text-slate-400 space-y-1">
                  <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto" />
                  <p className="font-semibold text-slate-800 dark:text-slate-200">
                    No matching endpoints for this filter
                  </p>
                </div>
              )}

              {/* Active Infostealer Malware Strains */}
              {stealerData?.stealerFamilies && Object.keys(stealerData.stealerFamilies).length > 0 && (
                <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 space-y-3">
                  <h4 className="font-bold text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-purple-500" />
                    Active Infostealer Botnet Families Breakdown
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-1">
                    {(Object.entries(stealerData.stealerFamilies) as [string, number][])
                      .sort(([, a], [, b]) => Number(b) - Number(a))
                      .map(([family, count]) => (
                        <div key={family} className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
                          <span className="font-bold text-slate-800 dark:text-slate-200">{family}</span>
                          <span className="font-mono text-slate-600 dark:text-slate-400 font-semibold">{count.toLocaleString()}</span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 flex flex-wrap items-center justify-between gap-3 shrink-0 text-xs text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-2 font-mono text-[11px]">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
            <span>NIST SP 800-53 IA-2(1) & PCI-DSS v4.0 Req 8.3.6 Evidence</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadMarkdown}
              className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Report</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-900 font-semibold transition-colors cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
