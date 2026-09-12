import React, { useState } from 'react';
import { EasmScanResult, SecurityFinding } from '../types';
import { OSINT_TOOLS, MITRE_TACTIC_LIST } from '../data/osintTools';
import { 
  Layers, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, 
  Info, ArrowRight, X, Sparkles, Filter, CheckCircle2 
} from 'lucide-react';

interface MitreMatrixTabProps {
  scan: EasmScanResult;
  onSelectOsintTool?: (toolId: string) => void;
}

interface TechniqueDefinition {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  adversaryBehavior: string;
  osintApproach: string;
  mitigation: string;
}

const MITRE_TECHNIQUES: TechniqueDefinition[] = [
  {
    id: 'T1596.001',
    name: 'Search Open Technical Databases: DNS',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries query open DNS servers and passive DNS databases to identify domains, subdomains, name servers, and IP addresses.',
    adversaryBehavior: 'Enumerates entire organizational domain zone to map auxiliary subdomains, development testbeds, and legacy portals.',
    osintApproach: 'Query tools like SecurityTrails, DNSDumpster, Robtex, and crt.sh to catalogue all historical and current zone records.',
    mitigation: 'Audit public DNS zones, eliminate legacy records, and implement split-horizon DNS for internal assets.'
  },
  {
    id: 'T1596.002',
    name: 'Search Open Technical Databases: WHOIS & RDAP',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries query public WHOIS and RDAP databases to discover domain registration details, administrative contacts, and registration expiration dates.',
    adversaryBehavior: 'Identifies corporate point-of-contacts for targeted phishing and monitors for impending domain expirations.',
    osintApproach: 'Inspect RDAP/WHOIS records via rdap.org, ICANN lookup, and ViewDNS.',
    mitigation: 'Enable WHOIS privacy protection, enable registry locking, and automate multi-year domain renewal.'
  },
  {
    id: 'T1596.003',
    name: 'Search Open Technical Databases: Digital Certificates (CT)',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries harvest public Certificate Transparency (CT) logs to discover newly provisioned hostnames and cryptographic parameters.',
    adversaryBehavior: 'Detects shadow IT deployments as soon as engineers request Let\'s Encrypt certificates for internal systems.',
    osintApproach: 'Search crt.sh, Censys Search, or Certspotter for wildcard and subdomain certificates.',
    mitigation: 'Deploy CAA (Certification Authority Authorization) DNS records and continuously monitor CT log streams with alert webhooks.'
  },
  {
    id: 'T1590.005',
    name: 'Gather Victim Network Info: IP Addresses & BGP/ASN',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries examine BGP routing tables, Autonomous System Numbers (ASNs), and IP allocation databases to identify organizational network perimeters.',
    adversaryBehavior: 'Finds entire IP CIDR blocks announced by the victim to conduct wide-net port and service sweeps.',
    osintApproach: 'Use BGPView, Hurricane Electric BGP Toolkit, and ARIN/RIPE databases to identify company IP blocks.',
    mitigation: 'Implement BGP Route Origin Authorization (ROA/RPKI) and minimize the footprint of corporate-owned IP blocks exposed directly.'
  },
  {
    id: 'T1592.002',
    name: 'Gather Victim Host Info: Software Identification',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries inspect HTTP response banners, error pages, and web headers to identify specific software types and version numbers.',
    adversaryBehavior: 'Identifies outdated server software (e.g. Apache 2.4.49) to select targeted remote code execution exploits.',
    osintApproach: 'Query Shodan, Censys, Wappalyzer, and HTTP Server headers to fingerprint perimeter software.',
    mitigation: 'Disable software version disclosures (server_tokens off, ServerTokens Prod) and suppress X-Powered-By headers.'
  },
  {
    id: 'T1592.004',
    name: 'Gather Victim Host Info: Client Configurations & Headers',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries analyze HTTP security headers (HSTS, CSP, X-Frame-Options) to gauge defense maturity and exploitability.',
    adversaryBehavior: 'Identifies missing HSTS to attempt SSL stripping, or missing X-Frame-Options for clickjacking on corporate portals.',
    osintApproach: 'Analyze headers via SecurityHeaders.com or automated curl/fetch inspection.',
    mitigation: 'Enforce HSTS preload, strict CSP nonces, X-Content-Type-Options: nosniff, and anti-framing directives.'
  },
  {
    id: 'T1593.003',
    name: 'Search Open Websites/Domains: Code Repositories',
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    description: 'Adversaries search public code repositories (GitHub, GitLab) for leaked employee credentials, API tokens, and internal endpoints.',
    adversaryBehavior: 'Harvests AWS secret access keys, database passwords, and internal staging URLs from commit histories.',
    osintApproach: 'Leverage GitGuardian HasMySecretLeaked, Trufflehog, and GitHub Advanced Code Search.',
    mitigation: 'Deploy pre-commit git secret scanners and enforce automated token revocation on secret leakage.'
  },
  {
    id: 'T1584.004',
    name: 'Compromise Infrastructure: Server & Subdomain Hijacking',
    tacticId: 'TA0042',
    tacticName: 'Resource Development',
    description: 'Adversaries claim abandoned third-party cloud resources (AWS S3, GitHub Pages, Heroku, Azure) that corporate CNAME records still point to.',
    adversaryBehavior: 'Takes over subdomains (e.g. dev.company.com) to host trusted phishing sites, harvest cookies, or bypass CORS.',
    osintApproach: 'Cross-reference CNAME pointers against the Can-I-Take-Over-XYZ signature database.',
    mitigation: 'Immediately purge dangling DNS CNAME records when decommissioning SaaS tools or cloud buckets.'
  },
  {
    id: 'T1566.002',
    name: 'Phishing: Domain Spoofing & Spearphishing Link',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries send malicious emails forging the victim organization\'s domain name to trick employees or clients into revealing credentials.',
    adversaryBehavior: 'Sends CEO fraud and fake invoice emails directly from the company\'s exact domain name.',
    osintApproach: 'Inspect SPF and DMARC enforcement using DMARCian or DoH TXT query tools.',
    mitigation: 'Deploy DMARC policy with p=reject, 100% enforcement, and automated RUA reporting.'
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    description: 'Adversaries leverage known vulnerabilities (CVEs) in public web applications, perimeter gateways, or APIs to execute code.',
    adversaryBehavior: 'Attacks unpatched perimeter VPN gateways, Citrix ADCs, or unauthenticated databases exposed to the internet.',
    osintApproach: 'Cross-reference exposed service banners against CISA Known Exploited Vulnerabilities (KEV) and NVD.',
    mitigation: 'Enforce rapid patching SLAs (under 48h for CISA KEV entries) and place administrative endpoints behind Zero Trust Network Access (ZTNA).'
  }
];

export const MitreMatrixTab: React.FC<MitreMatrixTabProps> = ({ scan, onSelectOsintTool }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueDefinition | null>(null);
  const [filterTactic, setFilterTactic] = useState<string>('ALL');

  // Find findings matching a technique
  const getFindingsForTechnique = (techId: string) => {
    return scan.findings.filter(f => 
      f.mitre.id === techId || 
      f.mitre.subId === techId || 
      techId.startsWith(f.mitre.id)
    );
  };

  // Find OSINT tools matching a technique
  const getToolsForTechnique = (techId: string) => {
    return OSINT_TOOLS.filter(t => 
      t.mitreMapping.techniqueId === techId || 
      techId.startsWith(t.mitreMapping.techniqueId)
    );
  };

  const tactics = ['ALL', 'TA0043', 'TA0042', 'TA0001'];

  const filteredTechniques = MITRE_TECHNIQUES.filter(t => 
    filterTactic === 'ALL' || t.tacticId === filterTactic
  );

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-3 transition-colors">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              MITRE ATT&CK Matrix for External Attack Surface Management
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Interactive kill-chain mapping connecting external reconnaissance & initial access vectors with active perimeter findings
            </p>
          </div>

          {/* Filter Tactic */}
          <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-950 p-1 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-mono">
            {tactics.map(tac => (
              <button
                key={tac}
                onClick={() => setFilterTactic(tac)}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer font-medium ${
                  filterTactic === tac
                    ? 'bg-blue-600 text-white font-semibold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {tac === 'ALL' ? 'All Tactics' : tac}
              </button>
            ))}
          </div>
        </div>

        {/* Matrix Grid: 3 Tactic Columns */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 pt-2">
          {MITRE_TACTIC_LIST.map((tactic) => {
            const techniquesInTactic = filteredTechniques.filter(t => t.tacticId === tactic.id);
            if (techniquesInTactic.length === 0) return null;

            return (
              <div key={tactic.id} className="space-y-3">
                {/* Tactic Column Header */}
                <div className={`p-3 rounded-xl border ${tactic.color} flex items-center justify-between`}>
                  <div>
                    <span className="text-[10px] uppercase font-mono font-bold tracking-wider block opacity-75">
                      {tactic.id}
                    </span>
                    <h3 className="font-bold text-sm text-slate-900 dark:text-slate-100">
                      {tactic.name}
                    </h3>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-white/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                    {techniquesInTactic.length} Techniques
                  </span>
                </div>

                {/* Technique Cards */}
                <div className="space-y-2.5">
                  {techniquesInTactic.map((tech) => {
                    const matchedFindings = getFindingsForTechnique(tech.id);
                    const matchedTools = getToolsForTechnique(tech.id);
                    const hasVulnerability = matchedFindings.length > 0;
                    const isSelected = selectedTechnique?.id === tech.id;

                    return (
                      <div
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-blue-50/70 dark:bg-blue-950/30 border-blue-500 shadow-sm ring-1 ring-blue-500'
                            : hasVulnerability
                            ? 'bg-red-50/50 dark:bg-red-950/20 border-red-200 dark:border-red-900/60 hover:border-red-400 dark:hover:border-red-700'
                            : 'bg-slate-50/50 dark:bg-slate-950/50 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="font-mono text-xs text-blue-600 dark:text-blue-400 font-semibold">
                            {tech.id}
                          </span>
                          {hasVulnerability ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 flex items-center gap-1 font-sans">
                              <ShieldAlert className="w-3 h-3 text-red-600 dark:text-red-400" />
                              {matchedFindings.length} Active Finding{matchedFindings.length > 1 ? 's' : ''}
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-500 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                              {matchedTools.length} Tools
                            </span>
                          )}
                        </div>

                        <h4 className="font-semibold text-xs text-slate-900 dark:text-slate-100 mt-1 line-clamp-2">
                          {tech.name}
                        </h4>

                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1.5 line-clamp-2 leading-relaxed">
                          {tech.description}
                        </p>

                        <div className="flex items-center justify-between pt-2 mt-2 border-t border-slate-200 dark:border-slate-800/80 text-[10px] text-slate-500 font-mono">
                          <span className="font-sans">Click for Deep-Dive</span>
                          <ArrowRight className="w-3 h-3 text-blue-600 dark:text-blue-400" />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Technique Deep-Dive Modal / Drawer */}
      {selectedTechnique && (
        <div className="bg-white dark:bg-slate-900 border border-blue-500/40 rounded-xl p-6 shadow-xl space-y-5 animate-in fade-in-50 transition-colors">
          <div className="flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/70 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 text-xs font-mono font-bold">
                  {selectedTechnique.id}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                  {selectedTechnique.tacticId}: {selectedTechnique.tacticName}
                </span>
              </div>
              <h3 className="text-xl font-bold text-slate-900 dark:text-white mt-1">
                {selectedTechnique.name}
              </h3>
            </div>

            <button
              onClick={() => setSelectedTechnique(null)}
              className="p-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
              <span className="text-red-600 dark:text-red-400 font-bold uppercase text-[10px] tracking-wider block font-sans">
                Adversary Procedure & Threat Intent
              </span>
              <p className="text-slate-700 dark:text-slate-300 font-sans text-xs leading-relaxed">
                {selectedTechnique.adversaryBehavior}
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
              <span className="text-emerald-600 dark:text-emerald-400 font-bold uppercase text-[10px] tracking-wider block font-sans">
                Enterprise Mitigation Strategy
              </span>
              <p className="text-slate-700 dark:text-slate-300 font-sans text-xs leading-relaxed">
                {selectedTechnique.mitigation}
              </p>
            </div>
          </div>

          {/* Active Target Findings Mapped Here */}
          {getFindingsForTechnique(selectedTechnique.id).length > 0 && (
            <div className="space-y-3 bg-red-50/60 dark:bg-red-950/20 border border-red-200 dark:border-red-900/60 rounded-xl p-4">
              <h4 className="text-xs font-bold text-red-700 dark:text-red-300 uppercase tracking-wider flex items-center gap-1.5 font-mono">
                <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400" />
                Active Target Findings on {scan.domain} Mapped to this Technique:
              </h4>

              <div className="space-y-2">
                {getFindingsForTechnique(selectedTechnique.id).map(f => (
                  <div key={f.id} className="p-3 rounded-lg bg-white dark:bg-slate-950/90 border border-red-200 dark:border-red-800/50 space-y-1 shadow-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 dark:text-slate-100 text-xs">{f.title}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-100 dark:bg-red-900/60 text-red-700 dark:text-red-300 font-bold">
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300 font-sans">{f.description}</p>
                    <div className="text-[11px] font-mono text-blue-600 dark:text-blue-400 pt-1">
                      Remediation: {f.remediation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Open OSINT Tools Mapping */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider font-mono">
              Curated OSINT Tools & Platforms for This Technique:
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {getToolsForTechnique(selectedTechnique.id).map(tool => (
                <div
                  key={tool.id}
                  className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-blue-400 dark:hover:border-blue-500/50 transition-all flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs text-slate-900 dark:text-slate-200">{tool.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white dark:bg-slate-900 text-blue-600 dark:text-blue-400 border border-slate-200 dark:border-slate-800">
                        {tool.pricing}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                      {tool.description}
                    </p>
                  </div>

                  <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-200 dark:border-slate-900">
                    <span className="text-[10px] font-mono text-slate-500 truncate max-w-[150px]">
                      Target: {tool.vulnerabilityTarget}
                    </span>
                    <a
                      href={tool.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-mono text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium"
                    >
                      <span>Launch Tool</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
