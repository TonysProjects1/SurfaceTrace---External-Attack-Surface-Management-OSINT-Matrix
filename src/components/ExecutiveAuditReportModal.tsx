import React, { useState } from 'react';
import { 
  X, 
  Download, 
  Printer, 
  Copy, 
  CheckCircle2, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  FileText, 
  Globe, 
  Server, 
  Bug, 
  Cpu, 
  Building2, 
  Check, 
  ArrowRight,
  Layers,
  ChevronDown
} from 'lucide-react';
import { EasmScanResult } from '../types';

interface ExecutiveAuditReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  scan: EasmScanResult;
}

export const ExecutiveAuditReportModal: React.FC<ExecutiveAuditReportModalProps> = ({
  isOpen,
  onClose,
  scan
}) => {
  const [copied, setCopied] = useState<string | null>(null);
  const [reportFormat, setReportFormat] = useState<'preview' | 'raw_markdown'>('preview');

  if (!isOpen) return null;

  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const criticalFindings = scan.findings.filter(f => f.severity === 'CRITICAL');
  const highFindings = scan.findings.filter(f => f.severity === 'HIGH');
  const mediumFindings = scan.findings.filter(f => f.severity === 'MEDIUM');
  const lowFindings = scan.findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO');

  const leakedCredentials = scan.vulnerabilities?.totalExposedCredentials || 0;
  const infectedEmployees = scan.vulnerabilities?.employeeLoginsCompromised || 0;
  const breachesCount = scan.vulnerabilities?.breaches?.length || 0;

  const generateMarkdown = () => {
    return `# EXTERNAL ATTACK SURFACE MANAGEMENT (EASM) EXECUTIVE AUDIT REPORT
**Document Classification:** CONFIDENTIAL // BOARD OF DIRECTORS BRIEFING  
**Target Enterprise Domain:** ${scan.domain}  
**Assessment Date:** ${dateStr}  
**Evaluating Platform:** SurfaceTrace Threat Intelligence & Attack Surface Management  
**Perimeter Health Score:** ${scan.overallScore}/100 (${scan.overallScore >= 80 ? 'GRADE A - SECURE' : scan.overallScore >= 60 ? 'GRADE B - MODERATE RISK' : 'GRADE C/D - CRITICAL EXPOSURE'})

---

## 1. EXECUTIVE OVERVIEW & THREAT SCORECARD
SurfaceTrace conducted an autonomous external reconnaissance audit targeting **${scan.domain}**. The assessment scanned internet-facing DNS zone apexes, public Certificate Transparency (CT) mirrors, cloud edge infrastructure, dark web infostealer telemetry, and authoritative breach repositories.

### Key Risk Metrics:
- **Perimeter Health Score:** ${scan.overallScore} / 100
- **Publicly Discovered Subdomains:** ${scan.subdomains.length}
- **Active Critical Severity Deficiencies:** ${criticalFindings.length}
- **Active High Severity Deficiencies:** ${highFindings.length}
- **Exfiltrated Credential Records:** ${leakedCredentials.toLocaleString()}
- **Malware-Infected Corporate Workstations:** ${infectedEmployees}
- **Authoritative Breaches Cataloged:** ${breachesCount}

---

## 2. PERIMETER TOPOLOGY & EDGE INFRASTRUCTURE
- **Apex IP Address:** ${scan.network?.ip || 'N/A'}
- **Autonomous System (ASN):** ${scan.network?.asn || 'Unknown'} (${scan.network?.asOrganization || 'N/A'})
- **Hosting Infrastructure:** ${scan.network?.asnCountry || 'Global Cloud Edge'}
- **Email Security Governance:** SPF: ${scan.emailSecurity?.spf?.status || 'Unknown'} | DMARC Policy: ${scan.emailSecurity?.dmarc?.policy || 'None'}
- **HTTP Transport Security:** TLS 1.3 / Defensive Headers Analyzed: ${scan.httpPosture?.headers?.length || 0} checked

---

## 3. HIGH & CRITICAL SECURITY DEFICIENCIES
${scan.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').map((f, i) => `
### ${i + 1}. [${f.severity}] ${f.title}
- **Category:** ${f.category}
- **Affected Asset:** ${f.evidence || scan.domain}
- **MITRE ATT&CK Mapping:** ${f.mitre ? `${f.mitre.id}: ${f.mitre.name} (${f.mitre.tacticName})` : 'N/A'}
- **Observed Threat:** ${f.description}
- **Remediation Action:** ${f.remediation}
`).join('\n')}

---

## 4. DARK WEB & INFOSTEALER BOTNET THREAT INTELLIGENCE
- **Total Compromised Credentials:** ${leakedCredentials.toLocaleString()}
- **Infected Corporate Employee Workstations:** ${infectedEmployees}
- **Client / Consumer Compromised Credentials:** ${scan.vulnerabilities?.stealerIntel?.usersInfected?.toLocaleString() || '0'}
- **Active Malware Botnet Strains:** ${scan.vulnerabilities?.stealerIntel?.stealerFamilies ? Object.keys(scan.vulnerabilities.stealerIntel.stealerFamilies).join(', ') : 'None detected'}

**Executive Risk Note:** Infostealers bypass Multi-Factor Authentication (MFA) by extracting active browser SQLite session cookies directly from compromised endpoints, allowing immediate session replay without password entry.

---

## 5. STATUTORY COMPLIANCE & FRAMEWORK ALIGNMENT
SurfaceTrace evaluated perimeter telemetry against global regulatory cybersecurity frameworks:
- **NIST SP 800-53 Rev. 5:** AC-4, SC-7, SC-8, IA-5 perimeter controls
- **CIS Controls v8:** Control 4 (Secure Configuration), Control 7 (Vulnerability Management), Control 9 (Email & Web Protections)
- **PCI-DSS v4.0:** Requirement 6.4.3 (Script/Header Integrity), Requirement 8.3 (MFA & Credential Hygiene)
- **ISO/IEC 27001:2022:** Annex A 8.20 (Network Security), Annex A 8.24 (Use of Cryptography)

---

## 6. PHASE-GATED REMEDIATION ROADMAP
### Phase 1: Immediate Containment (0 - 72 Hours)
1. **Invalidate Active Browser Sessions:** Force single-sign-on (SSO) session revocation and refresh tokens across all corporate identity providers (Okta, Entra ID, Google Workspace).
2. **Remediate Critical Findings:** Address ${criticalFindings.length} critical vulnerability findings.

### Phase 2: Tactical Hardening (7 - 30 Days)
1. **Enforce Strict DMARC Policy:** Transition from \`p=none\` monitoring to \`p=quarantine\` or \`p=reject\`.
2. **Decommission Dangling DNS Records:** Reclaim or delete dangling CNAME records pointing to inactive cloud services.

### Phase 3: Strategic Resilience (30 - 90 Days)
1. **FIDO2 / WebAuthn Hardware Keys:** Enforce origin-bound phishing-resistant credentials across all administrative roles.
2. **Continuous External Attack Surface Monitoring:** Automate daily Certificate Transparency and DoH monitoring.

---

## 7. MANAGEMENT SIGN-OFF & ATTESTATION
- **Chief Information Security Officer (CISO):** _________________________ Date: _________
- **Chief Legal Counsel / Compliance Officer:** _________________________ Date: _________
- **Lead Security Assessor:** SurfaceTrace Autonomous Engine Date: ${dateStr}
`;
  };

  const copyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdown());
    setCopied('markdown');
    setTimeout(() => setCopied(null), 2500);
  };

  const downloadMarkdown = () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `EASM_Executive_Audit_${scan.domain.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-md p-4 overflow-y-auto">
      <div 
        role="dialog" 
        aria-modal="true" 
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-5xl my-8 shadow-2xl flex flex-col max-h-[92vh] overflow-hidden text-slate-900 dark:text-slate-100"
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-950/70 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-600/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  Executive EASM Audit Assessment
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-200 dark:border-red-900">
                  Board-Ready Briefing
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                Target: {scan.domain} • Generated: {dateStr}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Format toggle */}
            <div className="flex items-center gap-1 bg-slate-200/80 dark:bg-slate-800 p-1 rounded-lg text-xs font-semibold">
              <button
                onClick={() => setReportFormat('preview')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                  reportFormat === 'preview'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Executive Layout
              </button>
              <button
                onClick={() => setReportFormat('raw_markdown')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                  reportFormat === 'raw_markdown'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Raw Markdown
              </button>
            </div>

            <button
              onClick={copyMarkdown}
              className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Copy full report as Markdown"
            >
              {copied === 'markdown' ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
              <span className="hidden sm:inline">{copied === 'markdown' ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={downloadMarkdown}
              className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Download report (.md)"
            >
              <Download className="w-4 h-4" />
              <span className="hidden sm:inline">Download</span>
            </button>

            <button
              onClick={handlePrint}
              className="p-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Print / Save as PDF"
            >
              <Printer className="w-4 h-4" />
              <span className="hidden sm:inline">Print / PDF</span>
            </button>

            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs leading-relaxed print:p-0">
          {reportFormat === 'raw_markdown' ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-slate-500 font-mono text-[11px]">
                <span>Standard CommonMark / Markdown v2.0</span>
                <span>{generateMarkdown().length.toLocaleString()} characters</span>
              </div>
              <pre className="p-4 rounded-xl bg-slate-950 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre-wrap border border-slate-800 select-all">
                {generateMarkdown()}
              </pre>
            </div>
          ) : (
            <div className="space-y-8 max-w-4xl mx-auto">
              {/* Report Banner */}
              <div className="border-b-2 border-slate-900 dark:border-slate-100 pb-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500 font-bold block">
                      Autonomous External Attack Surface Assessment
                    </span>
                    <h1 className="text-2xl font-black tracking-tight text-slate-900 dark:text-white mt-1">
                      {scan.domain.toUpperCase()}
                    </h1>
                  </div>
                  <div className="text-left sm:text-right">
                    <span className="text-xs font-mono text-slate-500 block">Assessment Authority: SurfaceTrace</span>
                    <span className="text-xs font-mono text-slate-500 block">Date of Issue: {dateStr}</span>
                    <span className="inline-block mt-1 px-2.5 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border border-red-300 dark:border-red-800">
                      RESTRICTED // BOARD DISCLOSURE
                    </span>
                  </div>
                </div>
              </div>

              {/* 1. Scorecard Grid */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2">
                  <span>1. Executive Scorecard & Key Risk Indicators</span>
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Health Score</span>
                    <div className="text-3xl font-black font-mono text-blue-600 dark:text-blue-400 mt-1">
                      {scan.overallScore}<span className="text-base text-slate-400">/100</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-semibold block mt-1">
                      {scan.overallScore >= 80 ? 'Grade A - Secure' : scan.overallScore >= 60 ? 'Grade B - Moderate' : 'Grade C/D - Critical'}
                    </span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Discovered Assets</span>
                    <div className="text-3xl font-black font-mono text-slate-900 dark:text-white mt-1">
                      {scan.subdomains.length}
                    </div>
                    <span className="text-[10px] text-slate-500 font-semibold block mt-1">
                      Active subdomains & endpoints
                    </span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Critical/High Issues</span>
                    <div className="text-3xl font-black font-mono text-red-600 dark:text-red-400 mt-1">
                      {criticalFindings.length + highFindings.length}
                    </div>
                    <span className="text-[10px] text-red-600 dark:text-red-400 font-semibold block mt-1">
                      {criticalFindings.length} Critical • {highFindings.length} High
                    </span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Leaked Credentials</span>
                    <div className="text-3xl font-black font-mono text-amber-600 dark:text-amber-400 mt-1 truncate">
                      {leakedCredentials > 0 ? leakedCredentials.toLocaleString() : '0'}
                    </div>
                    <span className="text-[10px] text-amber-600 dark:text-amber-400 font-semibold block mt-1">
                      {infectedEmployees} employee infection(s)
                    </span>
                  </div>
                </div>
              </div>

              {/* 2. Perimeter Topology */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                  2. Edge Routing & Perimeter Infrastructure
                </h3>
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase block">Apex IP Address</span>
                    <span className="font-mono text-slate-900 dark:text-white font-semibold text-xs mt-0.5 block">
                      {scan.network?.ip || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase block">Autonomous System (ASN)</span>
                    <span className="font-mono text-slate-900 dark:text-white font-semibold text-xs mt-0.5 block truncate">
                      {scan.network?.asn || 'Unknown'} ({scan.network?.asOrganization || 'Cloud Edge'})
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase block">Email Governance</span>
                    <span className="font-mono text-slate-900 dark:text-white font-semibold text-xs mt-0.5 block">
                      SPF: {scan.emailSecurity?.spf?.status || 'Unknown'} • DMARC: {scan.emailSecurity?.dmarc?.policy || 'None'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase block">Certificate Validity</span>
                    <span className="font-mono text-slate-900 dark:text-white font-semibold text-xs mt-0.5 block">
                      {scan.certificates.length} CT certificates indexed
                    </span>
                  </div>
                </div>
              </div>

              {/* 3. Top Security Deficiencies */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3 flex items-center justify-between">
                  <span>3. High & Critical Security Deficiencies</span>
                  <span className="text-[11px] font-normal text-slate-500">
                    Showing top {Math.min(6, criticalFindings.length + highFindings.length)} priority items
                  </span>
                </h3>

                <div className="space-y-3">
                  {criticalFindings.concat(highFindings).slice(0, 6).map((finding, idx) => (
                    <div 
                      key={idx}
                      className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 space-y-2"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            finding.severity === 'CRITICAL'
                              ? 'bg-red-600 text-white'
                              : 'bg-orange-500 text-white'
                          }`}>
                            {finding.severity}
                          </span>
                          <h4 className="font-bold text-xs text-slate-900 dark:text-white">
                            {finding.title}
                          </h4>
                        </div>
                        {finding.mitre && (
                          <span className="text-[10px] font-mono text-slate-500 bg-slate-200/60 dark:bg-slate-800 px-2 py-0.5 rounded">
                            MITRE: {finding.mitre.id}
                          </span>
                        )}
                      </div>

                      <p className="text-slate-600 dark:text-slate-300 text-xs">
                        {finding.description}
                      </p>

                      <div className="p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px]">
                        <strong className="text-slate-800 dark:text-slate-200">Required Remediation: </strong>
                        <span className="text-slate-600 dark:text-slate-400">{finding.remediation}</span>
                      </div>
                    </div>
                  ))}

                  {criticalFindings.length + highFindings.length === 0 && (
                    <div className="p-6 rounded-xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800/40 text-center text-emerald-800 dark:text-emerald-300">
                      <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto mb-1" />
                      <p className="font-semibold">Zero Critical or High severity issues detected.</p>
                      <p className="text-[11px] text-emerald-700 dark:text-emerald-400">
                        Perimeter adheres to standard baseline defensive hygiene.
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* 4. Infostealer Botnet Threat */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                  4. Dark Web & Infostealer Botnet Intelligence
                </h3>
                <div className="p-4 rounded-xl bg-red-50/70 dark:bg-red-950/20 border border-red-200 dark:border-red-900/60 space-y-3">
                  <div className="flex items-center gap-2 font-bold text-red-900 dark:text-red-200 text-xs">
                    <ShieldAlert className="w-4 h-4 text-red-600" />
                    <span>Session Hijacking & Active Corporate Host Infections</span>
                  </div>
                  <p className="text-xs text-red-800 dark:text-red-300 leading-relaxed">
                    SurfaceTrace identified <strong>{infectedEmployees} corporate employee host(s)</strong> compromised by active infostealer malware (RedLine, Lumma, Vidar). Infostealer malware harvests live SQLite browser cookies and authorization tokens, bypassing Multi-Factor Authentication (MFA) via Session Hijacking (MITRE T1539).
                  </p>
                </div>
              </div>

              {/* 5. Phase-Gated Remediation Plan */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                  5. Actionable 3-Phase Remediation Plan
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-red-600 dark:text-red-400 text-xs uppercase">
                      <span className="w-2 h-2 rounded-full bg-red-500"></span>
                      <span>Phase 1 (0 - 72 Hours)</span>
                    </div>
                    <ul className="space-y-1.5 text-[11px] text-slate-600 dark:text-slate-300">
                      <li>• Invalidate all corporate SSO user sessions and refresh tokens.</li>
                      <li>• Re-image infected employee workstations identified in botnet logs.</li>
                      <li>• Patch critical perimeter vulnerabilities.</li>
                    </ul>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-orange-600 dark:text-orange-400 text-xs uppercase">
                      <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                      <span>Phase 2 (7 - 30 Days)</span>
                    </div>
                    <ul className="space-y-1.5 text-[11px] text-slate-600 dark:text-slate-300">
                      <li>• Enforce strict email DMARC policy (<code className="font-mono text-[10px]">p=quarantine</code> / <code className="font-mono text-[10px]">p=reject</code>).</li>
                      <li>• Decommission dangling DNS CNAME records.</li>
                      <li>• Implement HSTS and defensive HTTP transport headers.</li>
                    </ul>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-blue-600 dark:text-blue-400 text-xs uppercase">
                      <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                      <span>Phase 3 (30 - 90 Days)</span>
                    </div>
                    <ul className="space-y-1.5 text-[11px] text-slate-600 dark:text-slate-300">
                      <li>• Transition all technical staff to FIDO2 / WebAuthn hardware security keys.</li>
                      <li>• Enforce automated Certificate Transparency and zone auditing.</li>
                      <li>• Conduct formal attack surface penetration testing.</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* 6. Formal Attestation & Sign-Off */}
              <div className="pt-6 border-t border-slate-200 dark:border-slate-800">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                  6. Executive Sign-Off & Verification
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl border border-slate-300 dark:border-slate-700 space-y-6">
                    <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                      Chief Information Security Officer (CISO)
                    </span>
                    <div className="border-b border-dashed border-slate-400 pt-8"></div>
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                      <span>Signature</span>
                      <span>Date</span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl border border-slate-300 dark:border-slate-700 space-y-6">
                    <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                      Chief Legal Counsel / Compliance
                    </span>
                    <div className="border-b border-dashed border-slate-400 pt-8"></div>
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                      <span>Signature</span>
                      <span>Date</span>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl border border-slate-300 dark:border-slate-700 space-y-6">
                    <span className="text-[11px] font-bold text-slate-800 dark:text-slate-200 block">
                      Lead Security Assessor (SurfaceTrace)
                    </span>
                    <div className="border-b border-dashed border-slate-400 pt-8"></div>
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                      <span>Verified Autonomous</span>
                      <span>{dateStr}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
