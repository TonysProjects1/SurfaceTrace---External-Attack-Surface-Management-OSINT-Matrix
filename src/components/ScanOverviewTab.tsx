import React, { useState } from 'react';
import { EasmScanResult, SecurityFinding, Severity } from '../types';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Info, CheckCircle2, 
  Download, Copy, ExternalLink, ArrowUpRight, Sparkles, Layers,
  Server, Globe, Mail, Lock, FileText, Check
} from 'lucide-react';

interface ScanOverviewTabProps {
  scan: EasmScanResult;
  onNavigateTab: (tab: string) => void;
  onSelectFindingForMitre?: (finding: SecurityFinding) => void;
}

const SEVERITY_CONFIG: Record<Severity, { bg: string; text: string; border: string; icon: React.ReactNode }> = {
  CRITICAL: {
    bg: 'bg-red-50/70 dark:bg-red-950/30',
    text: 'text-red-700 dark:text-red-400',
    border: 'border-red-200 dark:border-red-900/60',
    icon: <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
  },
  HIGH: {
    bg: 'bg-orange-50/70 dark:bg-orange-950/30',
    text: 'text-orange-700 dark:text-orange-400',
    border: 'border-orange-200 dark:border-orange-900/60',
    icon: <AlertTriangle className="w-4 h-4 text-orange-600 dark:text-orange-400" />
  },
  MEDIUM: {
    bg: 'bg-amber-50/70 dark:bg-amber-950/30',
    text: 'text-amber-700 dark:text-amber-400',
    border: 'border-amber-200 dark:border-amber-900/60',
    icon: <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
  },
  LOW: {
    bg: 'bg-blue-50/70 dark:bg-blue-950/30',
    text: 'text-blue-700 dark:text-blue-400',
    border: 'border-blue-200 dark:border-blue-900/60',
    icon: <Info className="w-4 h-4 text-blue-600 dark:text-blue-400" />
  },
  INFO: {
    bg: 'bg-slate-50 dark:bg-slate-900/80',
    text: 'text-slate-600 dark:text-slate-400',
    border: 'border-slate-200 dark:border-slate-800',
    icon: <CheckCircle2 className="w-4 h-4 text-slate-500 dark:text-slate-400" />
  }
};

export const ScanOverviewTab: React.FC<ScanOverviewTabProps> = ({
  scan,
  onNavigateTab,
  onSelectFindingForMitre
}) => {
  const [copied, setCopied] = useState(false);

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40';
      case 'B':
        return 'text-blue-700 dark:text-blue-400 border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-950/40';
      case 'C':
        return 'text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40';
      default:
        return 'text-red-700 dark:text-red-400 border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950/40';
    }
  };

  const handleCopySummary = () => {
    const markdown = `# External Attack Surface Assessment: ${scan.domain}
- **Scan Timestamp:** ${new Date(scan.scannedAt).toUTCString()}
- **Attack Surface Posture Score:** ${scan.overallScore}/100 (Grade: ${scan.grade})
- **Discovered Subdomains:** ${scan.subdomains.length}
- **Public Certificates:** ${scan.certificates.length}
- **Primary Hosting:** ${scan.network.hostingType || 'Standard'} (${scan.network.asn || 'N/A'})
- **Email Security:** DMARC=${scan.dns.emailSecurity.dmarc.status} (${scan.dns.emailSecurity.dmarc.policy || 'none'}), SPF=${scan.dns.emailSecurity.spf.status}

## Key Findings (${scan.findings.length} total):
${scan.findings.map(f => `- [${f.severity}] ${f.title} (MITRE: ${f.mitre.id} - ${f.mitre.name})`).join('\n')}

Generated via SurfaceTrace EASM Platform.`;

    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scan, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `easm-scan-${scan.domain}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportSubdomainsCsv = () => {
    const headers = "Subdomain,Status,Resolved_IP,CNAME_Target,Takeover_Risk\n";
    const rows = scan.subdomains.map(s => `"${s.subdomain}","${s.status}","${s.ip || ''}","${s.cname || ''}","${s.riskNote || ''}"`).join('\n');
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(headers + rows);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `subdomains-${scan.domain}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner with Score & Quick Actions */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs relative overflow-hidden transition-colors">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          {/* Domain & Target Identity */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white tracking-tight">
                {scan.domain}
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                {scan.network.hostingType || 'Public Cloud'}
              </span>
              {scan.whois.dnssec && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                  DNSSEC Active
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-2">
              <span>Target: <a href={scan.targetUrl} target="_blank" rel="noreferrer" className="text-blue-600 dark:text-blue-400 hover:underline font-mono">{scan.targetUrl}</a></span>
              <span>•</span>
              <span>Scanned {new Date(scan.scannedAt).toLocaleTimeString()} ({scan.scanDurationMs}ms)</span>
            </p>
          </div>

          {/* Score & Grade Dial */}
          <div className="flex items-center gap-5 bg-slate-50 dark:bg-slate-950/80 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800">
            <div className="text-right">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Posture Score
              </div>
              <div className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white font-mono">
                {scan.overallScore}<span className="text-sm font-normal text-slate-400">/100</span>
              </div>
            </div>
            <div className={`w-14 h-14 rounded-xl border-2 flex items-center justify-center font-black text-2xl font-mono shadow-xs ${getGradeColor(scan.grade)}`}>
              {scan.grade}
            </div>
          </div>

          {/* Export & Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto">
            <button
              onClick={handleCopySummary}
              className="flex-1 lg:flex-none inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-300 dark:border-slate-700 transition-colors shadow-xs cursor-pointer"
              title="Copy Markdown Summary to Clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
              <span>{copied ? 'Copied!' : 'Copy Summary'}</span>
            </button>
            <button
              onClick={handleExportJson}
              className="flex-1 lg:flex-none inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-300 dark:border-slate-700 transition-colors shadow-xs cursor-pointer"
              title="Export complete scan payload as JSON"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={handleExportSubdomainsCsv}
              className="flex-1 lg:flex-none inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-300 dark:border-slate-700 transition-colors shadow-xs cursor-pointer"
              title="Export discovered subdomains as CSV"
            >
              <FileText className="w-3.5 h-3.5 text-slate-500" />
              <span>CSV Assets</span>
            </button>
            <button
              onClick={() => onNavigateTab('ai-threat')}
              className="flex-1 lg:flex-none inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-lg bg-blue-50 hover:bg-blue-100 dark:bg-blue-950/50 dark:hover:bg-blue-900/50 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 text-xs font-semibold transition-all cursor-pointer shadow-xs"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              <span>AI Threat Simulation</span>
            </button>
          </div>
        </div>
      </div>

      {/* 4 Metric Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Subdomain Surface */}
        <div 
          onClick={() => onNavigateTab('footprint')} 
          className="bg-white dark:bg-slate-900 hover:border-blue-300 dark:hover:border-blue-700 border border-slate-200 dark:border-slate-800 rounded-xl p-5 transition-all cursor-pointer group shadow-xs"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Subdomain Surface</span>
            <Globe className="w-4 h-4 text-blue-600 dark:text-blue-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
            {scan.subdomains.length}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Discovered via CT logs & DNS probing
          </p>
        </div>

        {/* Card 2: Certificate Inventory */}
        <div 
          onClick={() => onNavigateTab('footprint')} 
          className="bg-white dark:bg-slate-900 hover:border-blue-300 dark:hover:border-blue-700 border border-slate-200 dark:border-slate-800 rounded-xl p-5 transition-all cursor-pointer group shadow-xs"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Public TLS Certs</span>
            <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
            {scan.certificates.length}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Indexed in Certificate Transparency logs
          </p>
        </div>

        {/* Card 3: Email Anti-Spoofing */}
        <div 
          onClick={() => onNavigateTab('posture')} 
          className="bg-white dark:bg-slate-900 hover:border-blue-300 dark:hover:border-blue-700 border border-slate-200 dark:border-slate-800 rounded-xl p-5 transition-all cursor-pointer group shadow-xs"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">DMARC / SPF Posture</span>
            <Mail className="w-4 h-4 text-blue-600 dark:text-blue-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="text-sm font-semibold capitalize">
            {scan.dns.emailSecurity.dmarc.status === 'enforced' ? (
              <span className="text-emerald-700 dark:text-emerald-400 flex items-center gap-1 font-medium">
                <CheckCircle2 className="w-4 h-4" /> Enforced ({scan.dns.emailSecurity.dmarc.policy})
              </span>
            ) : scan.dns.emailSecurity.dmarc.status === 'monitoring_only' ? (
              <span className="text-amber-700 dark:text-amber-400 flex items-center gap-1 font-medium">
                <AlertTriangle className="w-4 h-4" /> Monitoring Only (p=none)
              </span>
            ) : (
              <span className="text-red-700 dark:text-red-400 flex items-center gap-1 font-medium">
                <ShieldAlert className="w-4 h-4" /> Missing DMARC
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 truncate">
            SPF: {scan.dns.emailSecurity.spf.status} • MX: {scan.dns.emailSecurity.mx.records.length} servers
          </p>
        </div>

        {/* Card 4: Network & ASN */}
        <div 
          onClick={() => onNavigateTab('footprint')} 
          className="bg-white dark:bg-slate-900 hover:border-blue-300 dark:hover:border-blue-700 border border-slate-200 dark:border-slate-800 rounded-xl p-5 transition-all cursor-pointer group shadow-xs"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Autonomous System</span>
            <Server className="w-4 h-4 text-blue-600 dark:text-blue-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
          <div className="text-sm font-bold font-mono text-slate-900 dark:text-white truncate">
            {scan.network.asn || 'Private / Unknown'}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 truncate">
            {scan.network.asOrganization || scan.network.country || 'Global edge routing'}
          </p>
        </div>
      </div>

      {/* Prioritized Security Findings Section */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Prioritized Attack Surface Findings & Exposure Points
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Correlated against MITRE ATT&CK Reconnaissance & Initial Access techniques
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="px-2 py-0.5 rounded bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-semibold">
              {scan.summary.criticalCount} Critical
            </span>
            <span className="px-2 py-0.5 rounded bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-300 border border-orange-200 dark:border-orange-800 font-semibold">
              {scan.summary.highCount} High
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-semibold">
              {scan.summary.mediumCount} Medium
            </span>
            <span className="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-semibold">
              {scan.summary.lowCount} Low
            </span>
          </div>
        </div>

        {scan.findings.length === 0 ? (
          <div className="text-center py-12 text-slate-500 dark:text-slate-400">
            <ShieldCheck className="w-12 h-12 text-emerald-600 dark:text-emerald-400 mx-auto mb-2" />
            <p className="font-semibold text-slate-800 dark:text-slate-200">No high-severity attack surface exposures identified.</p>
            <p className="text-xs text-slate-500 mt-1">The perimeter exhibits strong DNS, transport, and header hygiene.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {scan.findings.map((finding) => {
              const sev = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;
              return (
                <div
                  key={finding.id}
                  className={`p-4 rounded-xl border ${sev.border} ${sev.bg} transition-all space-y-2`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-2.5">
                      {sev.icon}
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                        {finding.title}
                      </span>
                      <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-bold border ${sev.border} ${sev.text}`}>
                        {finding.severity}
                      </span>
                    </div>

                    {/* MITRE ATT&CK Tag */}
                    <button
                      onClick={() => onNavigateTab('mitre')}
                      className="self-start sm:self-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-[11px] font-mono text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 transition-colors cursor-pointer shadow-xs"
                      title="View technique in MITRE ATT&CK Matrix"
                    >
                      <Layers className="w-3 h-3 text-blue-600 dark:text-blue-400" />
                      <span>{finding.mitre.id}: {finding.mitre.name}</span>
                      <ArrowUpRight className="w-3 h-3 text-slate-400" />
                    </button>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    {finding.description}
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                      <span className="text-slate-500 dark:text-slate-400 block text-[10px] uppercase font-bold tracking-wider mb-0.5">Discovered Evidence</span>
                      <span className="text-slate-800 dark:text-slate-200 break-all">{finding.evidence}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800">
                      <span className="text-emerald-700 dark:text-emerald-400 block text-[10px] uppercase font-bold tracking-wider mb-0.5">Defensive Remediation</span>
                      <span className="text-slate-800 dark:text-slate-200">{finding.remediation}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
