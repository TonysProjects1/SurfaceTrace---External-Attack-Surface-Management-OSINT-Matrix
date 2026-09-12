import React from 'react';
import { X, BookOpen, CheckCircle2, Shield, Globe, Terminal, ArrowRight, Layers } from 'lucide-react';

interface AnalystPlaybookModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const PLAYBOOK_PHASES = [
  {
    phase: 'Phase 01',
    title: 'Passive Discovery & Perimeter Scoping',
    objective: 'Map the complete external digital footprint without generating active network traffic against target infrastructure.',
    tools: ['crt.sh', 'SecurityTrails', 'DNSDumpster', 'BGPView'],
    mitre: 'TA0043: T1596 (Search Open Technical Databases)',
    actions: [
      'Extract all historical and active subdomains from public Certificate Transparency logs (crt.sh).',
      'Audit BGP Autonomous System Numbers (ASNs) to catalogue all announced corporate IPv4/IPv6 CIDR blocks.',
      'Query historical passive DNS records to discover decommissioned servers still associated with DNS.'
    ]
  },
  {
    phase: 'Phase 02',
    title: 'Infrastructure & Dangling CNAME Audit',
    objective: 'Validate host resolution and detect infrastructure hijacking / subdomain takeover vulnerabilities.',
    tools: ['Can-I-Take-Over-XYZ', 'Cloudflare DoH', 'Subfinder'],
    mitre: 'TA0042: T1584.004 (Server Hijacking)',
    actions: [
      'Resolve all enumerated subdomains to identify NXDOMAIN status or unresolved DNS CNAME pointers.',
      'Audit pointers to third-party cloud providers (AWS S3, Heroku, Azure, GitHub Pages, Zendesk, Fastly).',
      'Immediately purge dangling CNAME records from DNS before external adversaries claim the backend resource.'
    ]
  },
  {
    phase: 'Phase 03',
    title: 'Transport & Web Security Posture Analysis',
    objective: 'Enforce cryptographic transport hygiene and defense-in-depth HTTP security headers.',
    tools: ['SecurityHeaders.com', 'SSL Labs', 'SurfaceTrace Scanner'],
    mitre: 'TA0043: T1592.004 (Client Configurations)',
    actions: [
      'Enforce Strict-Transport-Security (HSTS) with max-age >= 31536000, includeSubDomains, and preload.',
      'Deploy restrictive Content-Security-Policy (CSP) headers to prevent XSS and data exfiltration.',
      'Strip detailed web server version numbers from HTTP Server and X-Powered-By response headers.'
    ]
  },
  {
    phase: 'Phase 04',
    title: 'Identity, Email & Public Secret Exposure',
    objective: 'Neutralize domain spoofing in phishing and discover leaked credentials in open datasets.',
    tools: ['DMARCian', 'GitGuardian HasMySecretLeaked', 'GrayhatWarfare', 'HaveIBeenPwned'],
    mitre: 'TA0001: T1566 (Phishing) & TA0043: T1593.003 (Code Repositories)',
    actions: [
      'Elevate DMARC policy from p=none to p=quarantine and strictly to p=reject with 100% enforcement.',
      'Audit public GitHub and GitLab repositories for hardcoded corporate API keys, AWS credentials, and tokens.',
      'Search public AWS S3 buckets and Azure Blobs for exposed corporate backups (.bak, .sql) or PII.'
    ]
  },
  {
    phase: 'Phase 05',
    title: 'Continuous Remediation & Drift Monitoring',
    objective: 'Establish automated continuous monitoring to alert SOC teams the instant a new external asset appears.',
    tools: ['CISA KEV Catalog', 'ProjectDiscovery Chaos', 'Webhook Alerts'],
    mitre: 'TA0001: T1190 (Exploit Public-Facing Application)',
    actions: [
      'Cross-reference perimeter service versions against the CISA Known Exploited Vulnerabilities (KEV) catalog.',
      'Automate daily Certificate Transparency stream monitors to flag any new SSL certificate issued to corporate domains.',
      'Decommission legacy test and staging subdomains, migrating internal tools behind Zero Trust / SSO gateways.'
    ]
  }
];

export const AnalystPlaybookModal: React.FC<AnalystPlaybookModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs animate-in fade-in-50">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden transition-colors">
        {/* Modal Header */}
        <div className="p-6 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/60 flex items-center justify-center text-blue-600 dark:text-blue-400 shrink-0">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                External Attack Surface Management (EASM) Analyst Playbook
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                Standard 5-Phase SOC & Red Team Methodology for Perimeter Governance
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-6">
          <div className="space-y-4">
            {PLAYBOOK_PHASES.map((phase) => (
              <div
                key={phase.phase}
                className="bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800/80 rounded-xl p-4.5 space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-2.5">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/70 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 text-[10px] font-mono font-bold">
                      {phase.phase}
                    </span>
                    <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">
                      {phase.title}
                    </h3>
                  </div>

                  <span className="text-[11px] font-mono text-amber-700 dark:text-amber-400/90 self-start sm:self-auto font-medium">
                    MITRE: {phase.mitre}
                  </span>
                </div>

                <p className="text-xs text-slate-600 dark:text-slate-300 font-sans leading-relaxed">
                  {phase.objective}
                </p>

                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] uppercase font-mono font-bold text-slate-400 dark:text-slate-500 tracking-wider block font-sans">
                    Execution Checklist:
                  </span>
                  {phase.actions.map((act, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 font-sans">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                      <span>{act}</span>
                    </div>
                  ))}
                </div>

                <div className="flex flex-wrap items-center gap-1.5 pt-2 text-[10px] font-mono text-slate-500">
                  <span className="font-sans">Key Tools:</span>
                  {phase.tools.map(t => (
                    <span key={t} className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-blue-600 dark:text-blue-300">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/80 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono">
          <span>Enterprise EASM Framework v2.4</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold transition-colors cursor-pointer shadow-xs font-sans"
          >
            Close Playbook
          </button>
        </div>
      </div>
    </div>
  );
};
