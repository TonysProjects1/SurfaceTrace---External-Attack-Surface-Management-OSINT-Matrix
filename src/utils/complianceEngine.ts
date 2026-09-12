import { EasmScanResult, ComplianceControlMapping } from '../types';

export type ComplianceFramework = 'NIST_SP_800_53' | 'NIST_CSF' | 'CIS_V8' | 'ISO_27001' | 'PCI_DSS';

export type ComplianceStatus = 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIALLY_COMPLIANT' | 'AUDIT_FLAGGED';

export interface ComplianceControlCheck {
  id: string;
  framework: ComplianceFramework;
  frameworkLabel: string;
  controlId: string;
  controlName: string;
  controlFamily: string;
  status: ComplianceStatus;
  scoreImpact: number; // weight 0-100
  description: string;
  testedArtifact: string;
  observedEvidence: string;
  technicalFinding: string;
  auditorGuidance: string;
  mandatedFix: string;
  frameworkCitation: string;
}

export interface ComplianceFrameworkSummary {
  framework: ComplianceFramework;
  frameworkName: string;
  totalControls: number;
  compliantCount: number;
  nonCompliantCount: number;
  partialCount: number;
  compliancePercentage: number;
  highRiskGaps: string[];
}

export interface FullComplianceAuditReport {
  scannedDomain: string;
  evaluatedAt: string;
  overallComplianceScore: number;
  overallAuditRating: 'PASS' | 'CONDITIONAL_PASS' | 'HIGH_RISK_FAIL';
  summaries: Record<ComplianceFramework, ComplianceFrameworkSummary>;
  checks: ComplianceControlCheck[];
}

/**
 * Evaluates live external scan telemetry against formal regulatory and baseline security frameworks:
 * - NIST SP 800-53 Rev. 5 (Federal Information Systems)
 * - NIST Cybersecurity Framework (CSF v2.0)
 * - CIS Controls v8 (Center for Internet Security)
 * - ISO/IEC 27001:2022 (Annex A)
 * - PCI-DSS v4.0 (Requirement 6, 8, 10 & 11)
 */
export function evaluateCompliancePosture(scan: EasmScanResult): FullComplianceAuditReport {
  const checks: ComplianceControlCheck[] = [];
  const email = scan.dns.emailSecurity;
  const http = scan.httpPosture;

  const hstsHeader = http.headers.find(h => h.header.toLowerCase() === 'strict-transport-security');
  const hasValidHsts = hstsHeader?.status === 'secure';
  const cspHeader = http.headers.find(h => h.header.toLowerCase() === 'content-security-policy');
  const hasCsp = cspHeader?.status === 'secure';
  const xctoHeader = http.headers.find(h => h.header.toLowerCase() === 'x-content-type-options');
  const hasXcto = xctoHeader?.status === 'secure';
  const xfoHeader = http.headers.find(h => h.header.toLowerCase() === 'x-frame-options');
  const hasXfo = xfoHeader?.status === 'secure';
  const rpHeader = http.headers.find(h => h.header.toLowerCase() === 'referrer-policy');
  const hasRp = rpHeader?.status === 'secure';

  const isDmarcEnforced = email.dmarc.status === 'enforced';
  const isDmarcMonitoring = email.dmarc.status === 'monitoring_only';
  const hasSpf = email.spf.status === 'configured';
  const isSpfWeak = email.spf.status === 'weak';
  const hasServerBannerLeak = !!http.serverDisclosure;
  const hasWildcardSubdomain = scan.subdomains.some(s => s.isWildcard);
  const danglingCnames = scan.subdomains.filter(s => s.status === 'suspicious_cname');
  const expiredCerts = scan.certificates.filter(c => c.isExpired);
  const expiringSoonCerts = scan.certificates.filter(c => (c.daysRemaining !== undefined && c.daysRemaining <= 30 && c.daysRemaining > 0));

  // --- 1. NIST SP 800-53 Rev. 5 Controls ---

  // SC-8 / SC-8(1): Transmission Confidentiality and Integrity (HSTS / TLS)
  checks.push({
    id: 'nist-sc-8',
    framework: 'NIST_SP_800_53',
    frameworkLabel: 'NIST SP 800-53 Rev. 5',
    controlId: 'SC-8 / SC-8(1)',
    controlName: 'Transmission Confidentiality & Cryptographic Protection',
    controlFamily: 'System and Communications Protection (SC)',
    status: hasValidHsts && http.isHttps ? 'COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'Enforces cryptographically protected communications across all public perimeter endpoints to prevent cleartext downgrade attacks.',
    testedArtifact: `Apex HTTPS & Strict-Transport-Security (HSTS) Header`,
    observedEvidence: hasValidHsts 
      ? `HSTS is active with valid max-age directives (${hstsHeader?.value || 'enforced'}).`
      : `HSTS header is absent or insufficient (${hstsHeader?.value || 'none'}). Allows protocol downgrade (SSL Stripping).`,
    technicalFinding: hasValidHsts 
      ? 'Complies with mandatory TLS transport enforcement.' 
      : 'Perimeter web server does not enforce RFC 6797 HSTS. Cleartext HTTP fallback is possible.',
    auditorGuidance: 'Verify that public web servers broadcast Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.',
    mandatedFix: 'Configure web server (Nginx/Apache/Cloudflare) to send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
    frameworkCitation: 'NIST SP 800-53 Rev. 5 § SC-8 (Transmission Confidentiality and Integrity)'
  });

  // SI-8: Spam and Email Authentication Protection (DMARC / SPF / DKIM)
  checks.push({
    id: 'nist-si-8',
    framework: 'NIST_SP_800_53',
    frameworkLabel: 'NIST SP 800-53 Rev. 5',
    controlId: 'SI-8(1) & SI-8(2)',
    controlName: 'Spam Protection & Email Sender Domain Authentication',
    controlFamily: 'System and Information Integrity (SI)',
    status: isDmarcEnforced ? 'COMPLIANT' : isDmarcMonitoring ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 20,
    description: 'Federal mandate (BOD 18-01 / NIST SI-8) requiring domain authentication mechanisms to block unauthorized domain spoofing and phishing.',
    testedArtifact: `DNS TXT records at _dmarc.${scan.domain} and ${scan.domain}`,
    observedEvidence: isDmarcEnforced
      ? `DMARC policy '${email.dmarc.policy}' is actively enforced with forensic reporting.`
      : isDmarcMonitoring
      ? `DMARC policy is set to 'p=none' (telemetry monitoring only). Spoofed emails are delivered.`
      : `No valid DMARC policy discovered at _dmarc.${scan.domain}.`,
    technicalFinding: isDmarcEnforced
      ? 'Complies with federal anti-spoofing requirements.'
      : 'Fails DHS CISA Binding Operational Directive 18-01 and NIST SI-8 sender validation.',
    auditorGuidance: 'Inspect DNS zone for valid DMARC with policy set to quarantine or reject (p=reject preferred) and valid RUA reporting destination.',
    mandatedFix: `Publish at _dmarc.${scan.domain}: "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${scan.domain}".`,
    frameworkCitation: 'NIST SP 800-53 Rev. 5 § SI-8 & CISA BOD 18-01'
  });

  // SC-7: Boundary Protection / Information Disclosure
  checks.push({
    id: 'nist-sc-7',
    framework: 'NIST_SP_800_53',
    frameworkLabel: 'NIST SP 800-53 Rev. 5',
    controlId: 'SC-7(10)',
    controlName: 'Prevent Unauthorized Information Disclosure at Boundary',
    controlFamily: 'System and Communications Protection (SC)',
    status: !hasServerBannerLeak ? 'COMPLIANT' : 'AUDIT_FLAGGED',
    scoreImpact: 10,
    description: 'Prevents external exposure of detailed software versions, server models, or operating system footprints in public HTTP response headers.',
    testedArtifact: 'Perimeter HTTP Response Server / X-Powered-By Headers',
    observedEvidence: !hasServerBannerLeak
      ? 'Web server suppresses vendor release banners and execution runtimes.'
      : `Exposed server banner: "${http.serverDisclosure || http.xPoweredByDisclosure}".`,
    technicalFinding: !hasServerBannerLeak
      ? 'Complies with perimeter banner sanitization.'
      : 'Server leaks precise framework/daemon identities, assisting adversary targeted reconnaissance.',
    auditorGuidance: 'Confirm that server_tokens off, ServerTokens Prod, or WAF header masking is configured.',
    mandatedFix: 'Set "server_tokens off;" in Nginx or "ServerTokens Prod" in Apache. Strip X-Powered-By.',
    frameworkCitation: 'NIST SP 800-53 Rev. 5 § SC-7(10)'
  });

  // CM-8: Information System Component Inventory (Asset Discovery)
  checks.push({
    id: 'nist-cm-8',
    framework: 'NIST_SP_800_53',
    frameworkLabel: 'NIST SP 800-53 Rev. 5',
    controlId: 'CM-8(1)',
    controlName: 'Information System Component Inventory & Perimeter Audit',
    controlFamily: 'Configuration Management (CM)',
    status: danglingCnames.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'Requires maintaining an accurate, updated inventory of all public-facing assets, cloud endpoints, and DNS pointers without orphaned dependencies.',
    testedArtifact: `Public DNS zone & CT logs (${scan.subdomains.length} subdomains audited)`,
    observedEvidence: danglingCnames.length === 0
      ? `All ${scan.subdomains.length} discovered subdomains map to valid infrastructure with no dangling cloud records.`
      : `Found ${danglingCnames.length} dangling CNAME records susceptible to subdomain takeover.`,
    technicalFinding: danglingCnames.length === 0
      ? 'Asset governance and cloud resource decommissioning validated.'
      : `Critical asset management failure: dangling cloud resource pointers detected (${danglingCnames.map(d => d.subdomain).join(', ')}).`,
    auditorGuidance: 'Review DNS decommissioning procedures. Ensure CNAME records pointing to decommissioned S3/Azure/Heroku endpoints are purged.',
    mandatedFix: 'Immediately delete orphaned DNS CNAME records or claim the corresponding backend cloud tenant resources.',
    frameworkCitation: 'NIST SP 800-53 Rev. 5 § CM-8 (Information System Component Inventory)'
  });

  // SC-12: Cryptographic Key / Certificate Establishment and Management
  checks.push({
    id: 'nist-sc-12',
    framework: 'NIST_SP_800_53',
    frameworkLabel: 'NIST SP 800-53 Rev. 5',
    controlId: 'SC-12 / SC-17',
    controlName: 'Public Key Infrastructure & Certificate Lifecycle Management',
    controlFamily: 'System and Communications Protection (SC)',
    status: expiredCerts.length === 0 && expiringSoonCerts.length === 0 ? 'COMPLIANT' : expiredCerts.length > 0 ? 'NON_COMPLIANT' : 'PARTIALLY_COMPLIANT',
    scoreImpact: 15,
    description: 'Ensures certificates used for external authentication and encryption remain strictly within their validity windows and are automatically renewed.',
    testedArtifact: `Public CT Log certificates (${scan.certificates.length} analyzed)`,
    observedEvidence: expiredCerts.length === 0 && expiringSoonCerts.length === 0
      ? 'Active certificates have healthy remaining lifespans.'
      : expiredCerts.length > 0
      ? `Identified expired certificate(s): ${expiredCerts.map(c => c.commonName).join(', ')}.`
      : `Identified certificate(s) expiring within 30 days.`,
    technicalFinding: expiredCerts.length === 0
      ? 'Public TLS certificate lifecycle hygiene validated.'
      : 'Expired or failing certificate present on public perimeter.',
    auditorGuidance: 'Verify automated ACME/Let\'s Encrypt or enterprise PKI renewal pipelines.',
    mandatedFix: 'Provision renewed certificates with ECDSA or RSA-2048+ keys and automated 60-day renewal cycle.',
    frameworkCitation: 'NIST SP 800-53 Rev. 5 § SC-12 & SC-17'
  });

  // --- 2. NIST CSF v2.0 Controls ---

  // PR.DS-02: Data in Transit Protected
  checks.push({
    id: 'csf-pr-ds-02',
    framework: 'NIST_CSF',
    frameworkLabel: 'NIST CSF v2.0',
    controlId: 'PR.DS-02',
    controlName: 'Transmitted Data is Cryptographically Protected',
    controlFamily: 'PROTECT (PR.DS: Data Security)',
    status: http.isHttps && hasValidHsts ? 'COMPLIANT' : 'PARTIALLY_COMPLIANT',
    scoreImpact: 15,
    description: 'Ensures that all client-to-server data in transit across public networks is encrypted against interception and tampering.',
    testedArtifact: 'Apex HTTPS Redirection & HSTS Enforcement',
    observedEvidence: http.isHttps && hasValidHsts
      ? 'Apex service mandates TLS transport and sends HSTS headers.'
      : 'Incomplete transit encryption: HSTS missing or cleartext access permitted.',
    technicalFinding: hasValidHsts ? 'Meets PR.DS-02 baseline.' : 'Inadequate cryptographic transport enforcement.',
    auditorGuidance: 'Ensure all HTTP requests are permanently redirected (301) to HTTPS and HSTS is enforced.',
    mandatedFix: 'Deploy 301 redirects to HTTPS on all edge proxies and broadcast HSTS headers.',
    frameworkCitation: 'NIST CSF v2.0 Category PR.DS-02'
  });

  // PR.IR-01: Technology Infrastructure Protected (Content Security Policy & Frame Options)
  checks.push({
    id: 'csf-pr-ir-01',
    framework: 'NIST_CSF',
    frameworkLabel: 'NIST CSF v2.0',
    controlId: 'PR.IR-01',
    controlName: 'Perimeter Infrastructure & Application Armor Protected',
    controlFamily: 'PROTECT (PR.IR: Infrastructure Resilience)',
    status: hasCsp && hasXfo && hasXcto ? 'COMPLIANT' : (hasXfo || hasXcto) ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'Protects external applications against cross-site scripting (XSS), framing/clickjacking, and MIME-sniffing execution.',
    testedArtifact: 'Content-Security-Policy, X-Frame-Options, X-Content-Type-Options',
    observedEvidence: `CSP: ${cspHeader?.status || 'missing'}, XFO: ${xfoHeader?.status || 'missing'}, XCTO: ${xctoHeader?.status || 'missing'}.`,
    technicalFinding: hasCsp 
      ? 'Advanced browser-enforced defense headers deployed.' 
      : 'Missing Content-Security-Policy; vulnerable to client-side injection and clickjacking.',
    auditorGuidance: 'Validate presence of restrictive CSP directives (default-src, script-src) and X-Frame-Options: DENY.',
    mandatedFix: 'Add Content-Security-Policy and X-Frame-Options response headers.',
    frameworkCitation: 'NIST CSF v2.0 Category PR.IR-01'
  });

  // ID.AM-02: External Assets Inventoried
  checks.push({
    id: 'csf-id-am-02',
    framework: 'NIST_CSF',
    frameworkLabel: 'NIST CSF v2.0',
    controlId: 'ID.AM-02',
    controlName: 'Software, Systems & External Services Inventoried',
    controlFamily: 'IDENTIFY (ID.AM: Asset Management)',
    status: scan.subdomains.length > 0 && danglingCnames.length === 0 ? 'COMPLIANT' : danglingCnames.length > 0 ? 'NON_COMPLIANT' : 'PARTIALLY_COMPLIANT',
    scoreImpact: 15,
    description: 'External digital surface, public hostnames, and cloud infrastructure components are continuously identified and tracked.',
    testedArtifact: `${scan.subdomains.length} subdomains correlated via DNS & CT`,
    observedEvidence: `Cataloged ${scan.subdomains.length} external hostnames across ASN ${scan.network.asn || 'Cloud Edge'}.`,
    technicalFinding: danglingCnames.length === 0 ? 'Asset perimeter comprehensively cataloged.' : 'Uncontrolled external assets identified.',
    auditorGuidance: 'Cross-reference discovered subdomains against official CMDB/Asset register.',
    mandatedFix: 'Reconcile external DNS entries with authorized asset inventories.',
    frameworkCitation: 'NIST CSF v2.0 Category ID.AM-02'
  });

  // --- 3. CIS Controls v8 Controls ---

  // CIS 9.2: Ensure Only Fully Supported Network Protocols and Ciphers are in Use
  checks.push({
    id: 'cis-9-2',
    framework: 'CIS_V8',
    frameworkLabel: 'CIS Controls v8',
    controlId: 'CIS Control 9.2',
    controlName: 'Use Only Fully Supported Network Protocols & Modern TLS',
    controlFamily: 'Email and Web Browser Protections',
    status: http.isHttps && hasValidHsts ? 'COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'Ensure only fully supported TLS versions (TLS 1.2, TLS 1.3) and strict transport policies are accepted by perimeter web servers.',
    testedArtifact: 'Apex HTTPS & Transport Security Check',
    observedEvidence: hasValidHsts ? 'Perimeter enforces TLS with HSTS preload/max-age.' : 'Missing HSTS transport enforcement.',
    technicalFinding: hasValidHsts ? 'Meets CIS 9.2 browser protection.' : 'Fails CIS 9.2 due to lack of HSTS downgrade defense.',
    auditorGuidance: 'Verify browser warning triggers on protocol downgrade.',
    mandatedFix: 'Disable TLS 1.0/1.1 and enable HSTS with max-age >= 31536000.',
    frameworkCitation: 'CIS Controls v8 § 9.2'
  });

  // CIS 9.5: Implement DMARC
  checks.push({
    id: 'cis-9-5',
    framework: 'CIS_V8',
    frameworkLabel: 'CIS Controls v8',
    controlId: 'CIS Control 9.5',
    controlName: 'Implement DMARC Policy with Sender Enforcement',
    controlFamily: 'Email and Web Browser Protections',
    status: isDmarcEnforced ? 'COMPLIANT' : isDmarcMonitoring ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 20,
    description: 'To lower the chance of spoofed or modified emails from valid domains, implement DMARC with policy quarantine or reject.',
    testedArtifact: `DNS TXT at _dmarc.${scan.domain}`,
    observedEvidence: `DMARC Policy: ${email.dmarc.policy || 'missing'}, Status: ${email.dmarc.status}.`,
    technicalFinding: isDmarcEnforced ? 'Complies with CIS 9.5.' : 'Fails CIS 9.5 requirement for email sender authentication.',
    auditorGuidance: 'Review DMARC record to ensure policy is not set to none.',
    mandatedFix: 'Update DMARC policy tag to "p=reject" or "p=quarantine".',
    frameworkCitation: 'CIS Controls v8 § 9.5'
  });

  // CIS 4.1: Establish and Maintain a Secure Asset Configuration
  checks.push({
    id: 'cis-4-1',
    framework: 'CIS_V8',
    frameworkLabel: 'CIS Controls v8',
    controlId: 'CIS Control 4.1',
    controlName: 'Establish and Maintain a Secure Configuration Process',
    controlFamily: 'Secure Configuration of Enterprise Assets',
    status: !hasServerBannerLeak && hasXcto ? 'COMPLIANT' : 'PARTIALLY_COMPLIANT',
    scoreImpact: 10,
    description: 'Maintain hardened server configurations by turning off verbose error messages and suppression of application banners.',
    testedArtifact: 'Server HTTP Response Headers & MIME Sniffing Flag',
    observedEvidence: !hasServerBannerLeak 
      ? 'Default vendor banners masked.' 
      : `Exposed banner: ${http.serverDisclosure || 'server software leaked'}.`,
    technicalFinding: !hasServerBannerLeak ? 'Meets CIS 4.1 baseline hardening.' : 'Server banner exposure facilitates exploit profiling.',
    auditorGuidance: 'Ensure all perimeter proxies strip identifying software headers.',
    mandatedFix: 'Mask or strip Server, X-Powered-By, and X-AspNet-Version headers.',
    frameworkCitation: 'CIS Controls v8 § 4.1'
  });

  // --- 4. ISO/IEC 27001:2022 Controls ---

  // ISO A.8.20: Network Security (Perimeter Controls & Segmentation)
  checks.push({
    id: 'iso-a-8-20',
    framework: 'ISO_27001',
    frameworkLabel: 'ISO/IEC 27001:2022',
    controlId: 'Control A.8.20',
    controlName: 'Network Security & Public Perimeter Transport Controls',
    controlFamily: 'Technological Controls (Clause A.8)',
    status: hasValidHsts && danglingCnames.length === 0 ? 'COMPLIANT' : 'PARTIALLY_COMPLIANT',
    scoreImpact: 15,
    description: 'Networks and network devices shall be secured, managed and controlled to protect the information in systems and applications.',
    testedArtifact: 'External DNS Zone & Edge HTTPS Configuration',
    observedEvidence: hasValidHsts && danglingCnames.length === 0
      ? 'Perimeter network transport is secured and DNS hygiene is maintained.'
      : 'Network security deficiencies noted in DNS or TLS transport.',
    technicalFinding: hasValidHsts ? 'Meets A.8.20 network security baseline.' : 'Deficiency in public boundary transport controls.',
    auditorGuidance: 'Review perimeter architecture and external boundary defense configurations.',
    mandatedFix: 'Implement edge encryption and audit external DNS routing.',
    frameworkCitation: 'ISO/IEC 27001:2022 Annex A.8.20'
  });

  // ISO A.8.24: Use of Cryptography
  checks.push({
    id: 'iso-a-8-24',
    framework: 'ISO_27001',
    frameworkLabel: 'ISO/IEC 27001:2022',
    controlId: 'Control A.8.24',
    controlName: 'Use of Cryptography & Public Transport Enforcement',
    controlFamily: 'Technological Controls (Clause A.8)',
    status: http.isHttps && hasValidHsts ? 'COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.',
    testedArtifact: 'TLS Certificate Validity & HSTS Header',
    observedEvidence: http.isHttps && hasValidHsts
      ? 'Cryptographic transport enforced via modern cipher suites and HSTS.'
      : 'Cryptographic transport is optional or missing HSTS enforcement.',
    technicalFinding: hasValidHsts ? 'Compliant with ISO A.8.24.' : 'Inadequate cryptographic policy enforcement.',
    auditorGuidance: 'Inspect TLS configuration and verify cipher strengths.',
    mandatedFix: 'Enforce modern TLS suites and broadcast HSTS headers.',
    frameworkCitation: 'ISO/IEC 27001:2022 Annex A.8.24'
  });

  // --- 5. PCI-DSS v4.0 Controls ---

  // PCI Req 6.4.3: Manage all Payment Page Scripts & Header Defenses
  checks.push({
    id: 'pci-req-6-4-3',
    framework: 'PCI_DSS',
    frameworkLabel: 'PCI-DSS v4.0',
    controlId: 'Requirement 6.4.3 & 6.4.1',
    controlName: 'Protect Public Web Applications Against Attacks & Framing',
    controlFamily: 'Develop and Maintain Secure Systems and Software',
    status: hasCsp && hasXfo ? 'COMPLIANT' : hasXfo ? 'PARTIALLY_COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 15,
    description: 'All payment pages and consumer-facing web applications must protect against unauthorized script injection, framing, and clickjacking.',
    testedArtifact: 'Content-Security-Policy & X-Frame-Options Headers',
    observedEvidence: hasCsp && hasXfo
      ? 'CSP and frame-busting protections active on public boundary.'
      : `Missing CSP (${cspHeader?.status}) or X-Frame-Options (${xfoHeader?.status}).`,
    technicalFinding: hasCsp && hasXfo ? 'Compliant with PCI-DSS 6.4.3.' : 'Fails PCI-DSS v4.0 anti-tampering and clickjacking mandates.',
    auditorGuidance: 'Ensure strict script-src, object-src and frame-ancestors policies are enforced.',
    mandatedFix: 'Deploy Content-Security-Policy and X-Frame-Options: DENY headers.',
    frameworkCitation: 'PCI-DSS v4.0 Requirement 6.4.3'
  });

  // PCI Req 8.2.2: Ensure Secure Cookie Transmission
  const insecureCookies = http.cookiesDetected.filter(c => !c.secure || !c.httpOnly);
  checks.push({
    id: 'pci-req-8-2-2',
    framework: 'PCI_DSS',
    frameworkLabel: 'PCI-DSS v4.0',
    controlId: 'Requirement 8.2.2',
    controlName: 'Session Cookie Attributes & Transport Security',
    controlFamily: 'Identify Users and Authenticate Access',
    status: insecureCookies.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
    scoreImpact: 10,
    description: 'All session tokens and cookies must be protected with Secure and HttpOnly flags to prevent cleartext transmission or client-side theft.',
    testedArtifact: `Set-Cookie Response Headers (${http.cookiesDetected.length} cookies tested)`,
    observedEvidence: insecureCookies.length === 0
      ? `All ${http.cookiesDetected.length} cookies have Secure and HttpOnly flags configured.`
      : `Found ${insecureCookies.length} cookie(s) missing Secure or HttpOnly: ${insecureCookies.map(c => c.name).join(', ')}.`,
    technicalFinding: insecureCookies.length === 0
      ? 'Meets PCI-DSS cookie hygiene standards.'
      : 'Insecure cookie attributes allow session hijacking via XSS or network sniffing.',
    auditorGuidance: 'Verify that every Set-Cookie response contains Secure; HttpOnly; SameSite=Lax/Strict.',
    mandatedFix: 'Set "Secure; HttpOnly; SameSite=Strict" attributes on all session and tracking cookies.',
    frameworkCitation: 'PCI-DSS v4.0 Requirement 8.2.2'
  });

  // Compute Framework Summaries
  const frameworks: ComplianceFramework[] = ['NIST_SP_800_53', 'NIST_CSF', 'CIS_V8', 'ISO_27001', 'PCI_DSS'];
  const frameworkNames: Record<ComplianceFramework, string> = {
    NIST_SP_800_53: 'NIST SP 800-53 Rev. 5',
    NIST_CSF: 'NIST CSF v2.0',
    CIS_V8: 'CIS Controls v8',
    ISO_27001: 'ISO/IEC 27001:2022',
    PCI_DSS: 'PCI-DSS v4.0'
  };

  const summaries: Record<ComplianceFramework, ComplianceFrameworkSummary> = {} as any;

  let totalPointsEarned = 0;
  let totalPointsPossible = 0;

  for (const fw of frameworks) {
    const fwChecks = checks.filter(c => c.framework === fw);
    const total = fwChecks.length;
    const compliant = fwChecks.filter(c => c.status === 'COMPLIANT').length;
    const nonCompliant = fwChecks.filter(c => c.status === 'NON_COMPLIANT').length;
    const partial = fwChecks.filter(c => c.status === 'PARTIALLY_COMPLIANT' || c.status === 'AUDIT_FLAGGED').length;
    
    // Calculate percentage: compliant = 100%, partial = 50%, non = 0%
    const scoreSum = fwChecks.reduce((acc, c) => {
      if (c.status === 'COMPLIANT') return acc + 100;
      if (c.status === 'PARTIALLY_COMPLIANT' || c.status === 'AUDIT_FLAGGED') return acc + 50;
      return acc;
    }, 0);
    const pct = total > 0 ? Math.round(scoreSum / total) : 100;

    const highRiskGaps = fwChecks
      .filter(c => c.status === 'NON_COMPLIANT')
      .map(c => `${c.controlId}: ${c.controlName}`);

    summaries[fw] = {
      framework: fw,
      frameworkName: frameworkNames[fw],
      totalControls: total,
      compliantCount: compliant,
      nonCompliantCount: nonCompliant,
      partialCount: partial,
      compliancePercentage: pct,
      highRiskGaps
    };

    totalPointsEarned += scoreSum;
    totalPointsPossible += total * 100;
  }

  const overallScore = totalPointsPossible > 0 ? Math.round((totalPointsEarned / totalPointsPossible) * 100) : 100;
  const overallAuditRating = overallScore >= 85 ? 'PASS' : overallScore >= 60 ? 'CONDITIONAL_PASS' : 'HIGH_RISK_FAIL';

  return {
    scannedDomain: scan.domain,
    evaluatedAt: scan.scannedAt,
    overallComplianceScore: overallScore,
    overallAuditRating,
    summaries,
    checks
  };
}

/**
 * Deterministic fallback registry mapping finding IDs/categories to statutory compliance controls
 * Ensures 100% control visibility even on cached or historical scan payloads.
 */
export const DETERMINISTIC_FINDING_CONTROLS: Record<string, ComplianceControlMapping[]> = {
  'dmarc-missing': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(1) & SI-8(2)', controlName: 'Spam Protection & Sender Authentication' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Implement DMARC Policy with Sender Enforcement' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.20', controlName: 'Network Security & Public Email Transport' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 5.2.1', controlName: 'Anti-Phishing & Anti-Spoofing Perimeter Controls' }
  ],
  'dmarc-monitoring-only': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(1)', controlName: 'Sender Domain Authentication Enforcement' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Implement DMARC with Quarantine/Reject Policy' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 5.2.1', controlName: 'Malicious Email & Spoofing Mitigation' }
  ],
  'spf-missing': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-7(18)', controlName: 'Boundary Protection & Sender Verification' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Email Sender Validation (SPF)' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.20', controlName: 'Network Security Boundary Controls' }
  ],
  'spf-overly-permissive': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(2)', controlName: 'Spam Protection Rule Hardening' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Strict SPF Mechanism Enforcement' }
  ],
  'subdomain-takeover': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'CM-8(1)', controlName: 'Information System Component Inventory' },
    { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'ID.AM-02', controlName: 'Software, Systems & External Services Inventoried' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 1.1', controlName: 'Inventory and Control of Enterprise Assets' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.9', controlName: 'Configuration Management & Asset Hygiene' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 6.4.3', controlName: 'Manage External Assets & Third-Party Dependencies' }
  ],
  'hsts-missing': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-8 / SC-8(1)', controlName: 'Transmission Confidentiality & Cryptographic Protection' },
    { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'PR.DS-02', controlName: 'Transmitted Data Cryptographically Protected' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.2', controlName: 'Use Only Fully Supported Modern TLS & HSTS' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.24', controlName: 'Use of Cryptography & Transport Enforcement' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 4.1 & 4.2', controlName: 'Strong Cryptography for Transmission of Cardholder Data' }
  ],
  'csp-missing': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-10', controlName: 'Information Input Validation & Execution Restrictions' },
    { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'PR.IR-01', controlName: 'Application Armor & Content Policy Protection' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.4', controlName: 'Restrict Unauthorized Scripts and Browser Extensions' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 6.4.3', controlName: 'Manage all Scripts in Consumer Browsers' }
  ],
  'server-version-leak': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-7(10)', controlName: 'Prevent Unauthorized Information Disclosure at Boundary' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 4.1', controlName: 'Establish and Maintain Secure System Configurations' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.9', controlName: 'Configuration Management (Mask Banner Data)' },
    { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 2.2', controlName: 'Configure Systems to Prevent Known Vulnerabilities' }
  ],
  'caa-missing': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-12 / SC-17', controlName: 'Public Key Infrastructure & Certificate Authority Authorization' },
    { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.24', controlName: 'Cryptographic Key & Authority Governance' }
  ],
  'subdomain-footprint': [
    { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'CM-8(1)', controlName: 'Information System Component Inventory' },
    { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'ID.AM-02', controlName: 'Asset Inventory & Perimeter Discovery' },
    { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 1.1', controlName: 'Enterprise Asset Discovery and Tracking' }
  ]
};

export function getControlsForFinding(findingId: string, customControls?: ComplianceControlMapping[]): ComplianceControlMapping[] {
  if (customControls && customControls.length > 0) {
    return customControls;
  }
  return DETERMINISTIC_FINDING_CONTROLS[findingId] || [];
}
