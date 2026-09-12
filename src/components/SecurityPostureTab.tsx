import React, { useState } from 'react';
import { EasmScanResult, HttpHeaderCheck } from '../types';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, Info, Mail, Lock, 
  Terminal, CheckCircle2, Copy, Check, ExternalLink, Globe, ArrowRight,
  Scale, Award
} from 'lucide-react';

interface SecurityPostureTabProps {
  scan: EasmScanResult;
  onNavigateTab?: (tab: string) => void;
}

export const SecurityPostureTab: React.FC<SecurityPostureTabProps> = ({ scan, onNavigateTab }) => {
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippet(id);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const email = scan.dns.emailSecurity;
  const http = scan.httpPosture;

  return (
    <div className="space-y-6">
      {/* Quick Regulatory Mapping Banner */}
      <div className="bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-50 dark:bg-purple-950 border border-purple-200 dark:border-purple-800 text-purple-600 dark:text-purple-400 flex items-center justify-center shrink-0">
            <Scale className="w-4 h-4" />
          </div>
          <div>
            <div className="font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>Auditor Control Mapping (NIST SP 800-53 • NIST CSF • CIS v8 • ISO 27001 • PCI-DSS)</span>
            </div>
            <p className="text-slate-500 dark:text-slate-400 text-[11px] mt-0.5">
              Perimeter mail authentication, TLS transport enforcement, and browser headers map directly to federal and industry security baselines.
            </p>
          </div>
        </div>

        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('compliance')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold border border-slate-200 dark:border-slate-700 shadow-xs cursor-pointer transition-colors whitespace-nowrap self-start sm:self-auto"
          >
            <Award className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
            <span>Open Full Compliance Report</span>
          </button>
        )}
      </div>

      {/* 1. Email Security Posture (DMARC / SPF / MX) */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-5 transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold">
                NIST SI-8 • CIS 9.5 • CISA BOD 18-01
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Mail className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Email Authentication & Anti-Phishing Defense (DMARC / SPF / MX)
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Evaluates defense against domain spoofing, CEO impersonation, and Business Email Compromise (BEC)
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            {email.dmarc.status === 'enforced' ? (
              <span className="px-3 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-semibold flex items-center gap-1.5 font-sans">
                <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                Anti-Spoofing Enforced ({email.dmarc.policy})
              </span>
            ) : email.dmarc.status === 'monitoring_only' ? (
              <span className="px-3 py-1 rounded-full bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-semibold flex items-center gap-1.5 font-sans">
                <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
                DMARC Telemetry Only (p=none)
              </span>
            ) : (
              <span className="px-3 py-1 rounded-full bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-semibold flex items-center gap-1.5 font-sans">
                <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
                Vulnerable to Domain Spoofing
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* DMARC Panel */}
          <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider text-[11px] font-sans">
                DMARC Record (_dmarc.{scan.domain})
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                email.dmarc.status === 'enforced' ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800' :
                email.dmarc.status === 'monitoring_only' ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800' :
                'bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800'
              }`}>
                Policy: {email.dmarc.policy.toUpperCase()}
              </span>
            </div>

            <div className="bg-white dark:bg-slate-900/90 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 break-all">
              {email.dmarc.rawRecord || 'No TXT record found at _dmarc.' + scan.domain}
            </div>

            <div className="text-slate-600 dark:text-slate-400 space-y-1 font-sans text-[11px]">
              <div>
                <strong className="text-slate-800 dark:text-slate-200">Status:</strong> {email.dmarc.recommendation}
              </div>
              {email.dmarc.ruaMailto && (
                <div>
                  <strong className="text-slate-800 dark:text-slate-200">Reporting Mailbox (rua):</strong> <span className="font-mono text-blue-600 dark:text-blue-400">{email.dmarc.ruaMailto}</span>
                </div>
              )}
            </div>
          </div>

          {/* SPF Panel */}
          <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider text-[11px] font-sans">
                SPF Record (Sender Policy Framework)
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                email.spf.status === 'configured' ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800' :
                email.spf.status === 'weak' ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800' :
                'bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800'
              }`}>
                {email.spf.allFlag ? `Qualifier: ${email.spf.allFlag}` : 'SPF ' + email.spf.status.toUpperCase()}
              </span>
            </div>

            <div className="bg-white dark:bg-slate-900/90 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 break-all">
              {email.spf.rawRecord || 'No TXT record starting with v=spf1 found.'}
            </div>

            <div className="text-slate-600 dark:text-slate-400 space-y-1 font-sans text-[11px]">
              <div>
                <strong className="text-slate-800 dark:text-slate-200">Mechanisms ({email.spf.mechanisms.length}):</strong>{' '}
                <span className="font-mono text-blue-600 dark:text-blue-400">
                  {email.spf.mechanisms.join(', ') || 'None'}
                </span>
              </div>
              <div>
                <strong className="text-slate-800 dark:text-slate-200">Evaluation:</strong> {email.spf.recommendation}
              </div>
            </div>
          </div>
        </div>

        {/* MX Mail Gateways */}
        <div className="bg-slate-50 dark:bg-slate-950/60 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 dark:text-slate-400 font-sans">Detected Mail Gateways:</span>
            <span className="text-slate-800 dark:text-slate-200 font-semibold">
              {email.mx.providersDetected.join(', ') || 'No public MX handlers'}
            </span>
          </div>
          <div className="text-slate-500 font-sans">
            {email.mx.records.length} MX Records Active
          </div>
        </div>
      </div>

      {/* 2. Web & HTTP Security Headers Posture */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              HTTP Security Headers & Information Disclosure Audit
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Evaluates defense-in-depth headers protecting against XSS, clickjacking, MIME confusion, and version leakage
            </p>
          </div>

          <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
            Checked: <span className="text-blue-600 dark:text-blue-400 font-semibold">{http.urlChecked}</span> (HTTP {http.statusCode || 200})
          </div>
        </div>

        <div className="space-y-3">
          {http.headers.map((check, idx) => {
            const isSecure = check.status === 'secure';
            const isWarning = check.status === 'warning';
            const isLeak = check.status === 'leak';

            // NIST / Benchmark mapping helper
            const getHeaderComplianceTag = (hName: string) => {
              const lower = hName.toLowerCase();
              if (lower.includes('strict-transport-security')) return 'NIST SC-8 • NIST CSF PR.DS-02 • CIS 9.2 • ISO A.8.24';
              if (lower.includes('content-security-policy')) return 'NIST SC-7 • NIST CSF PR.IR-01 • PCI-DSS 6.4.3';
              if (lower.includes('x-frame-options')) return 'NIST SC-7 • PCI-DSS 6.4.3 • CWE-1021';
              if (lower.includes('x-content-type-options')) return 'NIST SC-7 • CIS 4.1 • CWE-79';
              if (lower.includes('referrer-policy')) return 'NIST SC-7 • Privacy Hygiene';
              if (lower.includes('server') || lower.includes('powered-by')) return 'NIST SC-7(10) • CIS 4.1 • CWE-200';
              return 'NIST SP 800-53 Baseline';
            };

            return (
              <div
                key={idx}
                className={`p-4 rounded-xl border transition-all ${
                  isSecure
                    ? 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-200 dark:border-slate-800'
                    : isLeak
                    ? 'bg-red-50/50 dark:bg-red-950/20 border-red-200 dark:border-red-900/60'
                    : isWarning
                    ? 'bg-amber-50/50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-900/60'
                    : 'bg-orange-50/50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-900/60'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2.5">
                    {isSecure ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    ) : isLeak ? (
                      <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    )}
                    <span className="font-bold text-sm text-slate-900 dark:text-slate-100 font-mono">
                      {check.header}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-50 dark:bg-purple-950/50 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 hidden md:inline-block">
                      {getHeaderComplianceTag(check.header)}
                    </span>
                  </div>

                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded font-bold border self-start sm:self-auto ${
                    isSecure ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800' :
                    isLeak ? 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800' :
                    isWarning ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800' :
                    'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800'
                  }`}>
                    {check.status}
                  </span>
                </div>

                <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                  {check.description}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <span className="text-slate-400 dark:text-slate-500 block text-[10px] uppercase font-bold tracking-wider mb-1 font-sans">
                      Observed Value
                    </span>
                    <span className={`break-all ${check.value ? 'text-slate-800 dark:text-slate-200' : 'text-slate-400 dark:text-slate-600 italic'}`}>
                      {check.value || 'Header Not Sent by Web Server'}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <span className="text-blue-600 dark:text-blue-400 block text-[10px] uppercase font-bold tracking-wider mb-1 font-sans">
                      Hardening Guidance
                    </span>
                    <span className="text-slate-700 dark:text-slate-300 font-sans text-[11px] leading-relaxed">
                      {check.recommendation}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Nginx & Apache Remediation Snippet */}
        <div className="bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 p-4 space-y-2 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-700 dark:text-slate-300 font-bold uppercase text-[11px] flex items-center gap-1.5 font-sans">
              <Terminal className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              Standard Production Nginx Hardening Snippet
            </span>
            <button
              onClick={() => handleCopy(
`# Nginx EASM Perimeter Hardening
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
server_tokens off;`, 'nginx')}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-[11px] font-sans font-medium border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer shadow-xs"
            >
              {copiedSnippet === 'nginx' ? <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
              <span>{copiedSnippet === 'nginx' ? 'Copied' : 'Copy Config'}</span>
            </button>
          </div>
          <pre className="text-slate-800 dark:text-slate-200 bg-white dark:bg-slate-900/80 p-3 rounded-lg border border-slate-200 dark:border-slate-800 text-[11px] overflow-x-auto leading-relaxed">
{`# Nginx EASM Perimeter Hardening
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
server_tokens off;`}
          </pre>
        </div>
      </div>
    </div>
  );
};
