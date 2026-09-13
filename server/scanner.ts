import { EasmScanResult, SecurityFinding, DnsRecord, SubdomainAsset, CertificateInfo, HttpHeaderCheck, EmailSecurityPosture, WhoisInfo, NetworkInfo, Severity, ComplianceControlMapping } from '../src/types';
import { fetchDomainVulnerabilityIntel } from './vulnerabilities';

// Fallback subdomains to check
const COMMON_SUBDOMAINS = [
  'www', 'api', 'mail', 'dev', 'staging', 'app', 'vpn', 'portal',
  'admin', 'cdn', 'test', 'remote', 'status', 'docs', 'auth', 'blog', 'shop'
];

// Vulnerable CNAME targets for subdomain takeover detection
const TAKEOVER_SIGNATURES = [
  { domain: 's3.amazonaws.com', provider: 'AWS S3 Bucket' },
  { domain: 's3-website', provider: 'AWS S3 Website' },
  { domain: 'herokuapp.com', provider: 'Heroku App' },
  { domain: 'herokudns.com', provider: 'Heroku DNS' },
  { domain: 'github.io', provider: 'GitHub Pages' },
  { domain: 'azurewebsites.net', provider: 'Microsoft Azure Web App' },
  { domain: 'trafficmanager.net', provider: 'Azure Traffic Manager' },
  { domain: 'cloudapp.net', provider: 'Microsoft Azure CloudApp' },
  { domain: 'zendesk.com', provider: 'Zendesk Portal' },
  { domain: 'fastly.net', provider: 'Fastly CDN' },
  { domain: 'readme.io', provider: 'Readme Documentation' },
  { domain: 'surge.sh', provider: 'Surge.sh' },
  { domain: 'bitbucket.io', provider: 'Bitbucket Cloud' },
  { domain: 'pantheonsite.io', provider: 'Pantheon Hosting' },
  { domain: 'ghost.io', provider: 'Ghost CMS' },
  { domain: 'myshopify.com', provider: 'Shopify Store' },
];

/**
 * Perform DNS-over-HTTPS queries using Cloudflare and Google DoH APIs
 */
async function queryDoh(name: string, type: string): Promise<any[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4500);
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const json = await res.json();
    return json.Answer || [];
  } catch (err) {
    // Fallback to Google DoH
    try {
      const gUrl = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4500);
      const res = await fetch(gUrl, { signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) return [];
      const json = await res.json();
      return json.Answer || [];
    } catch {
      return [];
    }
  }
}

/**
 * Query Certificate Transparency logs via crt.sh
 */
async function queryCrtSh(domain: string): Promise<{ subdomains: string[]; certs: CertificateInfo[] }> {
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
  const subdomains = new Set<string>();
  const certs: CertificateInfo[] = [];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 SurfaceTrace-EASM-Recon' }
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) {
        // Sort and pick most recent
        const slice = data.slice(0, 100);
        for (const item of slice) {
          const names = String(item.name_value || '').split('\n');
          for (let name of names) {
            name = name.trim().toLowerCase();
            if (name.startsWith('*.')) name = name.substring(2);
            if (name && (name === domain || name.endsWith(`.${domain}`))) {
              subdomains.add(name);
            }
          }

          if (item.issuer_name && certs.length < 15) {
            const notAfter = item.not_after ? new Date(item.not_after) : undefined;
            const isExpired = notAfter ? notAfter.getTime() < Date.now() : false;
            const daysRemaining = notAfter ? Math.round((notAfter.getTime() - Date.now()) / (1000 * 3600 * 24)) : undefined;

            certs.push({
              id: item.id,
              issuer: String(item.issuer_name || 'Unknown CA').split(',')[0].replace('CN=', '').trim(),
              commonName: String(item.common_name || domain),
              nameValue: String(item.name_value || ''),
              notBefore: item.not_before,
              notAfter: item.not_after,
              isExpired,
              daysRemaining
            });
          }
        }
      }
    }
  } catch (err) {
    // crt.sh timed out or failed; will rely on active probing
  }

  return { subdomains: Array.from(subdomains), certs };
}

/**
 * Inspect HTTP Security Headers and TLS status
 */
async function inspectHttp(domain: string): Promise<EasmScanResult['httpPosture']> {
  const targetUrl = `https://${domain}`;
  let statusCode = 0;
  let isHttps = false;
  let redirectsToHttps = false;
  let serverDisclosure: string | null = null;
  let xPoweredByDisclosure: string | null = null;
  const headersMap: Record<string, string> = {};
  const cookiesDetected: { name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[] = [];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SurfaceTrace-EASM/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    isHttps = true;
    redirectsToHttps = true;
    statusCode = res.status;

    res.headers.forEach((value, key) => {
      headersMap[key.toLowerCase()] = value;
    });

    // Check Set-Cookie headers
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const parts = setCookie.split(';');
      const name = parts[0]?.split('=')[0]?.trim() || 'SessionCookie';
      const secure = /secure/i.test(setCookie);
      const httpOnly = /httponly/i.test(setCookie);
      const sameSiteMatch = setCookie.match(/samesite=([^;]+)/i);
      cookiesDetected.push({
        name,
        secure,
        httpOnly,
        sameSite: sameSiteMatch ? sameSiteMatch[1] : undefined
      });
    }
  } catch (err) {
    // If HTTPS fails, test plain HTTP to check redirection
    try {
      const httpController = new AbortController();
      const httpTimeout = setTimeout(() => httpController.abort(), 4000);
      const httpRes = await fetch(`http://${domain}`, {
        method: 'HEAD',
        redirect: 'manual',
        headers: { 'User-Agent': 'Mozilla/5.0 SurfaceTrace-EASM' },
        signal: httpController.signal
      });
      clearTimeout(httpTimeout);
      statusCode = httpRes.status;
      const location = httpRes.headers.get('location') || '';
      if (location.startsWith('https://')) {
        redirectsToHttps = true;
      }
      httpRes.headers.forEach((value, key) => {
        headersMap[key.toLowerCase()] = value;
      });
    } catch {
      statusCode = 0;
    }
  }

  serverDisclosure = headersMap['server'] || null;
  xPoweredByDisclosure = headersMap['x-powered-by'] || headersMap['x-aspnet-version'] || null;

  // Build header checks
  const hstsVal = headersMap['strict-transport-security'];
  const cspVal = headersMap['content-security-policy'];
  const xfoVal = headersMap['x-frame-options'];
  const xctoVal = headersMap['x-content-type-options'];
  const refVal = headersMap['referrer-policy'];
  const permVal = headersMap['permissions-policy'];

  const headers: HttpHeaderCheck[] = [
    {
      header: 'Strict-Transport-Security (HSTS)',
      status: hstsVal ? 'secure' : 'missing',
      value: hstsVal || null,
      recommendation: hstsVal ? 'Configured properly. Ensure max-age >= 31536000 and consider preload.' : 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to prevent SSL stripping.',
      description: 'Forces browsers to only establish secure HTTPS connections, preventing man-in-the-middle downgrade attacks.'
    },
    {
      header: 'Content-Security-Policy (CSP)',
      status: cspVal ? 'secure' : 'missing',
      value: cspVal || null,
      recommendation: cspVal ? 'CSP is implemented. Verify restrictions on script-src, object-src, and default-src.' : 'Deploy a Content-Security-Policy header to restrict resources (scripts, styles, images) and prevent Cross-Site Scripting (XSS).',
      description: 'Restricts the domains and sources from which executable scripts and objects can be loaded into client browsers.'
    },
    {
      header: 'X-Frame-Options (Clickjacking)',
      status: xfoVal ? (['deny', 'sameorigin'].includes(xfoVal.toLowerCase()) ? 'secure' : 'warning') : 'missing',
      value: xfoVal || null,
      recommendation: xfoVal ? 'Protected against iframe clickjacking.' : 'Set X-Frame-Options to DENY or SAMEORIGIN (or frame-ancestors in CSP) to prevent UI redressing.',
      description: 'Prevents hostile external pages from framing your portal in an invisible iframe to hijack user clicks.'
    },
    {
      header: 'X-Content-Type-Options',
      status: (xctoVal && xctoVal.toLowerCase().includes('nosniff')) ? 'secure' : 'missing',
      value: xctoVal || null,
      recommendation: (xctoVal && xctoVal.toLowerCase().includes('nosniff')) ? 'MIME sniffing disabled.' : 'Set X-Content-Type-Options: nosniff to stop browsers from executing non-script files as scripts.',
      description: 'Stops browsers from MIME-sniffing a response away from the declared content-type.'
    },
    {
      header: 'Referrer-Policy',
      status: refVal ? 'secure' : 'warning',
      value: refVal || null,
      recommendation: refVal ? 'Referrer policy specified.' : 'Define Referrer-Policy: strict-origin-when-cross-origin to avoid leaking internal URL parameters in outbound referrers.',
      description: 'Governs how much referrer information (paths, tokens) is sent along with outbound requests.'
    },
    {
      header: 'Server Banner Information Leakage',
      status: (serverDisclosure && /\d/.test(serverDisclosure)) ? 'leak' : (serverDisclosure ? 'warning' : 'secure'),
      value: serverDisclosure,
      recommendation: (serverDisclosure && /\d/.test(serverDisclosure)) ? 'Strip detailed version numbers from the Server header to hinder automated CVE exploitation.' : 'Keep server tokens minimal or obfuscated.',
      description: 'Exposing exact web server software versions (e.g. Apache/2.4.49, nginx/1.18.0) enables adversaries to map targeted CVEs.'
    }
  ];

  return {
    urlChecked: targetUrl,
    isHttps,
    redirectsToHttps,
    statusCode,
    headers,
    serverDisclosure,
    xPoweredByDisclosure,
    cookiesDetected
  };
}

/**
 * Retrieve WHOIS / RDAP Information
 */
async function queryRdap(domain: string): Promise<WhoisInfo> {
  const info: WhoisInfo = {
    nameServers: []
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'Accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      info.registrar = data.entities?.find((e: any) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'Public Registrar';

      const events = data.events || [];
      const regEvent = events.find((e: any) => e.eventAction === 'registration');
      const expEvent = events.find((e: any) => e.eventAction === 'expiration');

      if (regEvent?.eventDate) {
        info.creationDate = regEvent.eventDate;
        const regDate = new Date(regEvent.eventDate);
        info.domainAgeYears = Math.max(0, Math.floor((Date.now() - regDate.getTime()) / (1000 * 3600 * 24 * 365.25)));
      }

      if (expEvent?.eventDate) {
        info.expirationDate = expEvent.eventDate;
        const expDate = new Date(expEvent.eventDate);
        info.daysToExpiration = Math.round((expDate.getTime() - Date.now()) / (1000 * 3600 * 24));
      }

      if (Array.isArray(data.nameservers)) {
        info.nameServers = data.nameservers.map((ns: any) => ns.ldhName || ns.name).filter(Boolean);
      }

      info.dnssec = Boolean(data.secureDNS?.delegationSigned);
    }
  } catch (err) {
    // RDAP query non-fatal
  }

  return info;
}

/**
 * Query IP & ASN network footprint
 */
async function queryNetwork(ip: string): Promise<NetworkInfo> {
  const net: NetworkInfo = {
    ip,
    hostingType: 'Standard Hosting'
  };

  if (!ip) return net;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,city,as,org,isp,reverse`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        net.country = data.country;
        net.city = data.city;
        net.asn = data.as;
        net.asOrganization = data.org || data.isp;
        net.reverseDns = data.reverse;

        const combined = `${data.as} ${data.org} ${data.isp}`.toLowerCase();
        if (combined.includes('cloudflare')) net.hostingType = 'Cloudflare CDN';
        else if (combined.includes('amazon') || combined.includes('aws')) net.hostingType = 'AWS';
        else if (combined.includes('google')) net.hostingType = 'Google Cloud';
        else if (combined.includes('microsoft') || combined.includes('azure')) net.hostingType = 'Microsoft Azure';
        else if (combined.includes('fastly')) net.hostingType = 'Fastly';
        else if (combined.includes('akamai')) net.hostingType = 'Akamai';
        else if (combined.includes('digitalocean')) net.hostingType = 'DigitalOcean';
      }
    }
  } catch {
    // non-fatal
  }

  return net;
}

/**
 * Core Orchestrator: Scan target domain attack surface
 */
export async function performEasmScan(rawDomain: string): Promise<EasmScanResult> {
  const startTime = Date.now();

  // Normalize domain
  let domain = rawDomain.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '');

  if (!domain || !domain.includes('.')) {
    throw new Error('Please provide a valid Fully Qualified Domain Name (e.g. example.com)');
  }

  // 1. Fetch DNS records in parallel
  const [aAnswers, aaaaAnswers, mxAnswers, txtAnswers, nsAnswers, cnameAnswers, soaAnswers, caaAnswers, dmarcAnswers] = await Promise.all([
    queryDoh(domain, 'A'),
    queryDoh(domain, 'AAAA'),
    queryDoh(domain, 'MX'),
    queryDoh(domain, 'TXT'),
    queryDoh(domain, 'NS'),
    queryDoh(domain, 'CNAME'),
    queryDoh(domain, 'SOA'),
    queryDoh(domain, 'CAA'),
    queryDoh(`_dmarc.${domain}`, 'TXT'),
  ]);

  const dnsRecords: DnsRecord[] = [];
  const addRecords = (answers: any[], type: string) => {
    for (const a of answers) {
      dnsRecords.push({
        type,
        name: a.name || domain,
        data: String(a.data || '').replace(/^"|"$/g, ''),
        ttl: a.TTL
      });
    }
  };

  addRecords(aAnswers, 'A');
  addRecords(aaaaAnswers, 'AAAA');
  addRecords(mxAnswers, 'MX');
  addRecords(txtAnswers, 'TXT');
  addRecords(nsAnswers, 'NS');
  addRecords(cnameAnswers, 'CNAME');
  addRecords(soaAnswers, 'SOA');
  addRecords(caaAnswers, 'CAA');

  // Primary IP
  const primaryIp = aAnswers[0]?.data || aaaaAnswers[0]?.data || '';

  // 2. Email Security Posture (SPF, DMARC, MX)
  const spfRecordObj = txtAnswers.find((t: any) => String(t.data || '').toLowerCase().includes('v=spf1'));
  const rawSpf = spfRecordObj ? String(spfRecordObj.data).replace(/^"|"$/g, '') : null;
  const spfMechanisms = rawSpf ? rawSpf.split(/\s+/).filter(m => m && !m.startsWith('v=')) : [];
  const allFlag = spfMechanisms.find(m => m.endsWith('all')) || null;
  const isOverlyPermissive = allFlag === '+all' || allFlag === '?all';

  const dmarcRecordObj = dmarcAnswers.find((t: any) => String(t.data || '').toLowerCase().includes('v=dmarc1'));
  const rawDmarc = dmarcRecordObj ? String(dmarcRecordObj.data).replace(/^"|"$/g, '') : null;
  let dmarcPolicy: 'reject' | 'quarantine' | 'none' | 'missing' = 'missing';
  let dmarcRua: string | undefined = undefined;
  let dmarcPct: number | undefined = undefined;

  if (rawDmarc) {
    const policyMatch = rawDmarc.match(/p=([^;\s]+)/i);
    const ruaMatch = rawDmarc.match(/rua=mailto:([^;\s]+)/i);
    const pctMatch = rawDmarc.match(/pct=(\d+)/i);

    if (policyMatch) {
      const pol = policyMatch[1].toLowerCase();
      if (pol === 'reject') dmarcPolicy = 'reject';
      else if (pol === 'quarantine') dmarcPolicy = 'quarantine';
      else if (pol === 'none') dmarcPolicy = 'none';
    }
    if (ruaMatch) dmarcRua = ruaMatch[1];
    if (pctMatch) dmarcPct = parseInt(pctMatch[1], 10);
  }

  const mxRecords = mxAnswers.map((m: any) => {
    const parts = String(m.data || '').split(/\s+/);
    return {
      priority: parseInt(parts[0], 10) || 10,
      host: parts[1] || parts[0]
    };
  });

  const emailSecurity: EmailSecurityPosture = {
    spf: {
      status: !rawSpf ? 'missing' : (isOverlyPermissive ? 'weak' : 'configured'),
      rawRecord: rawSpf,
      mechanisms: spfMechanisms,
      allFlag,
      isOverlyPermissive,
      recommendation: !rawSpf 
        ? 'Publish a valid SPF record with strict -all or ~all to prevent unauthorized email relays.'
        : (isOverlyPermissive ? 'Replace +all or ?all with ~all (softfail) or -all (hardfail).' : 'SPF record is active.')
    },
    dmarc: {
      status: !rawDmarc ? 'missing' : (dmarcPolicy === 'none' ? 'monitoring_only' : 'enforced'),
      rawRecord: rawDmarc,
      policy: dmarcPolicy,
      ruaMailto: dmarcRua,
      pct: dmarcPct,
      recommendation: !rawDmarc
        ? 'Configure a DMARC policy (_dmarc record) with p=quarantine or p=reject to neutralize domain spoofing and phishing.'
        : (dmarcPolicy === 'none' ? 'Elevate policy from p=none (monitoring only) to p=quarantine or p=reject to block spoofed messages.' : 'DMARC is enforced with active policy.')
    },
    mx: {
      hasMx: mxRecords.length > 0,
      records: mxRecords,
      providersDetected: Array.from(new Set(mxRecords.map(m => {
        const h = m.host.toLowerCase();
        if (h.includes('google') || h.includes('aspmx')) return 'Google Workspace';
        if (h.includes('outlook') || h.includes('microsoft')) return 'Microsoft 365 / Exchange';
        if (h.includes('pphosted') || h.includes('proofpoint')) return 'Proofpoint Email Security';
        if (h.includes('mimecast')) return 'Mimecast';
        if (h.includes('zoho')) return 'Zoho Mail';
        return 'Custom Mail Transfer Agent';
      })))
    }
  };

  // 3. Certificate Transparency, Subdomain Discovery, and Breach Intelligence
  const [{ subdomains: ctSubdomains, certs }, httpPosture, whois, network, vulnerabilities] = await Promise.all([
    queryCrtSh(domain),
    inspectHttp(domain),
    queryRdap(domain),
    queryNetwork(primaryIp),
    fetchDomainVulnerabilityIntel(domain)
  ]);

  // Combine CT subdomains with common wordlist
  const candidateSubdomains = Array.from(new Set([
    ...COMMON_SUBDOMAINS.map(s => `${s}.${domain}`),
    ...ctSubdomains
  ])).slice(0, 40); // Cap probe to 40 for responsiveness

  // Probe subdomains via DoH
  const subdomainAssets: SubdomainAsset[] = [];
  const probeBatch = candidateSubdomains.slice(0, 18);
  const probeResults = await Promise.all(probeBatch.map(async (sub) => {
    try {
      const [aAns, cnameAns] = await Promise.all([
        queryDoh(sub, 'A'),
        queryDoh(sub, 'CNAME')
      ]);

      const ip = aAns[0]?.data;
      const cname = cnameAns[0]?.data ? String(cnameAns[0].data).replace(/\.$/, '') : undefined;

      let status: SubdomainAsset['status'] = ip ? 'active' : (cname ? 'unresolved' : 'ct_discovered');
      let riskNote: string | undefined = undefined;

      if (cname) {
        const match = TAKEOVER_SIGNATURES.find(sig => cname.toLowerCase().includes(sig.domain));
        if (match) {
          if (!ip) {
            status = 'suspicious_cname';
            riskNote = `Dangling CNAME to ${match.provider}. Potential Subdomain Takeover!`;
          } else {
            riskNote = `Points to ${match.provider} (${cname})`;
          }
        }
      }

      return {
        subdomain: sub,
        ip,
        cname,
        isWildcard: sub.startsWith('*.'),
        status,
        riskNote
      };
    } catch {
      return {
        subdomain: sub,
        status: 'ct_discovered' as const
      };
    }
  }));

  subdomainAssets.push(...probeResults);

  // Add remainder of CT subdomains as discovered
  for (const ctSub of ctSubdomains.slice(18)) {
    if (!subdomainAssets.some(s => s.subdomain === ctSub)) {
      subdomainAssets.push({
        subdomain: ctSub,
        status: 'ct_discovered'
      });
    }
  }

  // 4. Generate Security Findings & Map to MITRE ATT&CK
  const findings: SecurityFinding[] = [];
  let deduction = 0;

  // Check 1: DMARC Enforcement
  if (emailSecurity.dmarc.status === 'missing') {
    deduction += 20;
    findings.push({
      id: 'dmarc-missing',
      title: 'Missing DMARC Policy (Domain Spoofing Vulnerability)',
      severity: 'HIGH',
      category: 'DNS & Email',
      description: 'The organization lacks an authoritative DMARC record on _dmarc.domain. Threat actors can send forged emails that impersonate executives and corporate identity without sender verification.',
      evidence: 'No TXT record found at _dmarc.' + domain,
      remediation: 'Publish a TXT record at _dmarc.' + domain + ' containing "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@' + domain + '; pct=100;".',
      mitre: {
        id: 'T1566',
        subId: 'T1566.002',
        name: 'Phishing: Spearphishing Link / Domain Spoofing',
        tacticId: 'TA0001',
        tacticName: 'Initial Access',
        description: 'Adversaries may send phishing messages to gain access to victim systems. Absent DMARC facilitates email sender header forgery.',
        adversaryUse: 'Spoofs CEO or HR identity to trick employees into providing credentials or executing wire transfers.',
        defenderMitigation: 'M1054: Software Configuration (Enforce DMARC, SPF, and DKIM).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(1) & SI-8(2)', controlName: 'Spam Protection & Sender Authentication' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Implement DMARC Policy with Sender Enforcement' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.20', controlName: 'Network Security & Public Email Transport' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 5.2.1', controlName: 'Anti-Phishing & Anti-Spoofing Perimeter Controls' }
      ]
    });
  } else if (emailSecurity.dmarc.policy === 'none') {
    deduction += 10;
    findings.push({
      id: 'dmarc-monitoring-only',
      title: 'DMARC Policy in Monitoring-Only Mode (p=none)',
      severity: 'MEDIUM',
      category: 'DNS & Email',
      description: 'The DMARC policy is set to p=none. While telemetry reports are collected, receiving mail servers will not block or quarantine unauthorized spoofed emails.',
      evidence: `Record: ${emailSecurity.dmarc.rawRecord}`,
      remediation: 'Progressively migrate policy from p=none to p=quarantine and ultimately p=reject.',
      mitre: {
        id: 'T1566',
        subId: 'T1566.002',
        name: 'Phishing: Spearphishing Link / Domain Spoofing',
        tacticId: 'TA0001',
        tacticName: 'Initial Access',
        description: 'Permissive p=none policies allow spoofed phishing emails to reach user inboxes unhindered.',
        adversaryUse: 'Sends spearphishing lures from legitimate company domain name.',
        defenderMitigation: 'M1054: Update DMARC policy to p=reject.'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(1)', controlName: 'Sender Domain Authentication Enforcement' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Implement DMARC with Quarantine/Reject Policy' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 5.2.1', controlName: 'Malicious Email & Spoofing Mitigation' }
      ]
    });
  }

  // Check 2: SPF Record
  if (emailSecurity.spf.status === 'missing') {
    deduction += 15;
    findings.push({
      id: 'spf-missing',
      title: 'Missing SPF Record',
      severity: 'HIGH',
      category: 'DNS & Email',
      description: 'No Sender Policy Framework (SPF) record was detected in DNS. Receiving mail agents cannot verify authorized sending MTAs.',
      evidence: 'No TXT record matching v=spf1 on root domain.',
      remediation: 'Deploy a valid SPF record (e.g. "v=spf1 include:_spf.google.com ~all") specifying all authorized mail sources.',
      mitre: {
        id: 'T1566',
        name: 'Phishing',
        tacticId: 'TA0001',
        tacticName: 'Initial Access',
        description: 'Adversaries exploit unauthenticated mail relays to send phishing campaigns.',
        adversaryUse: 'Leverages unauthenticated domain identity to bypass spam filters.',
        defenderMitigation: 'M1054: Configure SPF mechanisms and align with DKIM.'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-7(18)', controlName: 'Boundary Protection & Sender Verification' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Email Sender Validation (SPF)' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.20', controlName: 'Network Security Boundary Controls' }
      ]
    });
  } else if (emailSecurity.spf.isOverlyPermissive) {
    deduction += 10;
    findings.push({
      id: 'spf-overly-permissive',
      title: 'Overly Permissive SPF Record (+all or ?all)',
      severity: 'MEDIUM',
      category: 'DNS & Email',
      description: 'The SPF record ends with +all or ?all, effectively allowing any IP on the internet to legitimately deliver mail as this domain.',
      evidence: `Record: ${emailSecurity.spf.rawRecord}`,
      remediation: 'Change terminal mechanism to ~all (SoftFail) or -all (HardFail).',
      mitre: {
        id: 'T1566',
        name: 'Phishing',
        tacticId: 'TA0001',
        tacticName: 'Initial Access',
        description: 'Permissive SPF flags neutralize anti-spoofing controls.',
        adversaryUse: 'Delivers spoofed messages directly to victims.',
        defenderMitigation: 'M1054: Enforce strict SPF syntax.'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-8(2)', controlName: 'Spam Protection Rule Hardening' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.5', controlName: 'Strict SPF Mechanism Enforcement' }
      ]
    });
  }

  // Check 3: Dangling Subdomain / Subdomain Takeover
  const takeoverCandidate = subdomainAssets.find(s => s.status === 'suspicious_cname');
  if (takeoverCandidate) {
    deduction += 30;
    findings.push({
      id: 'subdomain-takeover',
      title: `Critical Dangling Subdomain Risk (${takeoverCandidate.subdomain})`,
      severity: 'CRITICAL',
      category: 'Exposed Assets',
      description: `The subdomain ${takeoverCandidate.subdomain} has a CNAME record pointing to a third-party cloud service (${takeoverCandidate.cname}) that does not resolve. An adversary can register this resource on the provider and claim control of the subdomain.`,
      evidence: `CNAME: ${takeoverCandidate.cname} -> Unresolved IP`,
      remediation: `Immediately delete the DNS CNAME record for ${takeoverCandidate.subdomain} or reclaim the cloud resource in your vendor account.`,
      mitre: {
        id: 'T1584',
        subId: 'T1584.004',
        name: 'Compromise Infrastructure: Server Hijacking',
        tacticId: 'TA0042',
        tacticName: 'Resource Development',
        description: 'Adversaries may hijack domain names or subdomains to host malicious content or harvest session cookies.',
        adversaryUse: 'Claims abandoned cloud bucket/app to execute trusted phishing, host malware with valid SSL certs, or steal session cookies.',
        defenderMitigation: 'M1030: Network Segmentation & DNS Hygiene Auditing.'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'CM-8(1)', controlName: 'Information System Component Inventory' },
        { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'ID.AM-02', controlName: 'Software, Systems & External Services Inventoried' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 1.1', controlName: 'Inventory and Control of Enterprise Assets' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.9', controlName: 'Configuration Management & Asset Hygiene' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 6.4.3', controlName: 'Manage External Assets & Third-Party Dependencies' }
      ]
    });
  }

  // Check 4: HSTS Header
  const hstsCheck = httpPosture.headers.find(h => h.header.includes('HSTS'));
  if (hstsCheck?.status === 'missing') {
    deduction += 10;
    findings.push({
      id: 'hsts-missing',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      severity: 'MEDIUM',
      category: 'Web & Transport',
      description: 'The server does not transmit the Strict-Transport-Security header. Browsers may establish initial connections over unencrypted HTTP, exposing sessions to man-in-the-middle downgrade attacks.',
      evidence: 'Strict-Transport-Security header not present in HTTP response.',
      remediation: 'Implement "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" in web server or CDN configuration.',
      mitre: {
        id: 'T1592',
        subId: 'T1592.004',
        name: 'Gather Victim Host Information: Client Configurations',
        tacticId: 'TA0043',
        tacticName: 'Reconnaissance',
        description: 'Adversaries profile transport configurations to identify downgrade opportunities.',
        adversaryUse: 'Performs SSL stripping or intercepts sensitive tokens over plaintext Wi-Fi.',
        defenderMitigation: 'M1038: Execution Prevention (Enforce HTTPS everywhere with HSTS).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-8 / SC-8(1)', controlName: 'Transmission Confidentiality & Cryptographic Protection' },
        { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'PR.DS-02', controlName: 'Transmitted Data Cryptographically Protected' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.2', controlName: 'Use Only Fully Supported Modern TLS & HSTS' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.24', controlName: 'Use of Cryptography & Transport Enforcement' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 4.1 & 4.2', controlName: 'Strong Cryptography for Transmission of Cardholder Data' }
      ]
    });
  }

  // Check 5: Content Security Policy
  const cspCheck = httpPosture.headers.find(h => h.header.includes('CSP'));
  if (cspCheck?.status === 'missing') {
    deduction += 8;
    findings.push({
      id: 'csp-missing',
      title: 'Missing Content Security Policy (CSP)',
      severity: 'LOW',
      category: 'Web & Transport',
      description: 'No Content-Security-Policy header was observed. Client browsers lack directive restrictions on script execution sources, amplifying Cross-Site Scripting (XSS) exploitability.',
      evidence: 'Content-Security-Policy header absent.',
      remediation: 'Define a restrictive CSP policy restricting script-src, style-src, and object-src.',
      mitre: {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tacticId: 'TA0001',
        tacticName: 'Initial Access',
        description: 'Lack of CSP allows injected payloads to execute scripts or exfiltrate tokens.',
        adversaryUse: 'Executes malicious JavaScript via XSS to steal authentication tokens.',
        defenderMitigation: 'M1050: Exploit Protection (Deploy strict Content-Security-Policy).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SI-10', controlName: 'Information Input Validation & Execution Restrictions' },
        { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'PR.IR-01', controlName: 'Application Armor & Content Policy Protection' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 9.4', controlName: 'Restrict Unauthorized Scripts and Browser Extensions' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 6.4.3', controlName: 'Manage all Scripts in Consumer Browsers' }
      ]
    });
  }

  // Check 6: Server Banner Version Leakage
  if (httpPosture.serverDisclosure && /\d/.test(httpPosture.serverDisclosure)) {
    deduction += 8;
    findings.push({
      id: 'server-version-leak',
      title: `Server Software Version Disclosure (${httpPosture.serverDisclosure})`,
      severity: 'LOW',
      category: 'Exposed Assets',
      description: `The web server transmits specific software and version numbers in the Server header (${httpPosture.serverDisclosure}). This simplifies targeted CVE mapping for attackers.`,
      evidence: `Header "Server: ${httpPosture.serverDisclosure}"`,
      remediation: 'Configure server to disable signature banners (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx).',
      mitre: {
        id: 'T1592',
        subId: 'T1592.002',
        name: 'Gather Victim Host Information: Software',
        tacticId: 'TA0043',
        tacticName: 'Reconnaissance',
        description: 'Adversaries search banners to discover exact versions with known public CVEs.',
        adversaryUse: 'Queries exploit databases for published weaponized exploits against identified server version.',
        defenderMitigation: 'M1054: Software Configuration (Suppress server banner disclosures).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-7(10)', controlName: 'Prevent Unauthorized Information Disclosure at Boundary' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 4.1', controlName: 'Establish and Maintain Secure System Configurations' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.9', controlName: 'Configuration Management (Mask Banner Data)' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 2.2', controlName: 'Configure Systems to Prevent Known Vulnerabilities' }
      ]
    });
  }

  // Check 7: CAA Record
  const hasCaa = dnsRecords.some(r => r.type === 'CAA');
  if (!hasCaa) {
    deduction += 5;
    findings.push({
      id: 'caa-missing',
      title: 'Missing DNS Certification Authority Authorization (CAA) Record',
      severity: 'LOW',
      category: 'DNS & Email',
      description: 'No CAA records were found in DNS. Any public Certificate Authority worldwide can issue certificates for this domain, increasing exposure to rogue or compromised CAs.',
      evidence: 'No CAA DNS records found.',
      remediation: 'Add CAA records specifying only authorized certificate authorities (e.g. "0 issue letsencrypt.org").',
      mitre: {
        id: 'T1596',
        subId: 'T1596.003',
        name: 'Search Open Technical Databases: Digital Certificates',
        tacticId: 'TA0043',
        tacticName: 'Reconnaissance',
        description: 'Attackers examine certificate issuance patterns to identify trusted CAs or obtain rogue certificates.',
        adversaryUse: 'Attempts to obtain illegitimate certificates via compromised or lenient CAs.',
        defenderMitigation: 'M1030: Network Infrastructure (Deploy CAA DNS records).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'SC-12 / SC-17', controlName: 'Public Key Infrastructure & Certificate Authority Authorization' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.8.24', controlName: 'Cryptographic Key & Authority Governance' }
      ]
    });
  }

  // Check 8: Informational CT Discovery
  if (subdomainAssets.length > 5) {
    findings.push({
      id: 'subdomain-footprint',
      title: `Public Subdomain Surface Detected (${subdomainAssets.length} Discovered Assets)`,
      severity: 'INFO',
      category: 'Exposed Assets',
      description: `Discovered ${subdomainAssets.length} public subdomains via Certificate Transparency logs and DNS enumeration. Each exposed host expands the organization's external attack surface.`,
      evidence: `Found ${subdomainAssets.length} hosts including ${subdomainAssets.slice(0, 3).map(s => s.subdomain).join(', ')}...`,
      remediation: 'Perform continuous asset inventory audits. Decommission unused test/staging subdomains and enforce centralized WAF coverage.',
      mitre: {
        id: 'T1596',
        subId: 'T1596.001',
        name: 'Search Open Technical Databases: DNS Records',
        tacticId: 'TA0043',
        tacticName: 'Reconnaissance',
        description: 'Adversaries query open CT and DNS databases to inventory all public perimeter systems.',
        adversaryUse: 'Maps all auxiliary systems to find unmonitored staging or legacy portals.',
        defenderMitigation: 'M1030: Network Segmentation (Isolate non-production subdomains behind VPN/Zero Trust).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'CM-8(1)', controlName: 'Information System Component Inventory' },
        { framework: 'NIST_CSF', frameworkLabel: 'NIST CSF v2.0', controlId: 'ID.AM-02', controlName: 'Asset Inventory & Perimeter Discovery' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 1.1', controlName: 'Enterprise Asset Discovery and Tracking' }
      ]
    });
  }

  // Check 9: Leaked Credentials & Infostealer Malware Infections
  if (vulnerabilities && vulnerabilities.employeeLoginsCompromised > 0) {
    deduction += Math.min(25, vulnerabilities.employeeLoginsCompromised * 4);
    const topUrls = vulnerabilities.stealerIntel?.topCompromisedUrls
      ?.filter(u => u.type === 'Employee')
      ?.map(u => u.url)
      ?.slice(0, 3)
      ?.join(', ') || `corporate login portals for ${domain}`;

    findings.push({
      id: 'credentials-stealer-compromised',
      title: `Compromised Employee Credentials in Infostealer Malware Logs (${vulnerabilities.employeeLoginsCompromised} Infected Corporate Hosts)`,
      severity: 'CRITICAL',
      category: 'Exposed Assets',
      description: `Cybercrime threat intelligence feeds (Hudson Rock Cavalier) identified ${vulnerabilities.employeeLoginsCompromised} corporate endpoints infected with infostealer malware (e.g. RedLine, Lumma, Vidar). Stolen telemetry includes active browser session cookies, cleartext passwords, and authentication tokens for endpoints such as ${topUrls}.`,
      evidence: `Active infostealer infections: ${vulnerabilities.employeeLoginsCompromised} employee computers, ${vulnerabilities.clientCredentialsCompromised} client accounts. Most recent employee infection: ${vulnerabilities.stealerIntel?.lastEmployeeCompromised || 'Recently detected'}.`,
      remediation: 'Immediately revoke active browser sessions and OAuth tokens for affected users, enforce mandatory password resets, and mandate phishing-resistant FIDO2 / WebAuthn hardware security keys to prevent session cookie theft.',
      mitre: {
        id: 'T1539',
        subId: 'T1589.001',
        name: 'Steal Web Session Cookie & Compromised Credentials',
        tacticId: 'TA0006',
        tacticName: 'Credential Access',
        description: 'Adversaries harvest session cookies and credentials from infostealer botnet logs to bypass multi-factor authentication and access corporate systems without generating new login alerts.',
        adversaryUse: 'Imports stolen session cookies into browser or tool (e.g. Cookie-Editor) to authenticate directly into corporate SSO/dashboards.',
        defenderMitigation: 'M1027: Password Policies & M1032: Multi-factor Authentication (FIDO2 / WebAuthn token binding).'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'IA-2(1)', controlName: 'Multi-Factor Authentication to Access Accounts' },
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'IA-5', controlName: 'Authenticator Management & Credential Revocation' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 5.4', controlName: 'Restrict and Revoke Stolen Credential Sets' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 8.3.6', controlName: 'Validate Authentication Credentials Against Known Compromises' },
        { framework: 'ISO_27001', frameworkLabel: 'ISO/IEC 27001:2022', controlId: 'Control A.5.17', controlName: 'Authentication Information & Credential Security' }
      ]
    });
  } else if (vulnerabilities && vulnerabilities.breaches.length > 0) {
    deduction += Math.min(15, vulnerabilities.breaches.length * 5);
    const breachTitles = vulnerabilities.breaches.map(b => b.Title).slice(0, 3).join(', ');
    findings.push({
      id: 'historical-domain-breaches',
      title: `Historical Corporate Domain Breaches Indexed (${vulnerabilities.breaches.length} Incidents in HaveIBeenPwned)`,
      severity: 'HIGH',
      category: 'Domain Governance',
      description: `The corporate domain has been impacted by ${vulnerabilities.breaches.length} historical data breach incident(s) (${breachTitles}), exposing corporate email addresses, hashes, and employee records in public leak archives.`,
      evidence: `Indexed breaches: ${breachTitles}. Total documented compromised accounts: ${vulnerabilities.totalExposedCredentials.toLocaleString()}.`,
      remediation: 'Audit active corporate accounts for password reuse across personal services. Enforce enterprise password manager usage and continuous breach monitoring.',
      mitre: {
        id: 'T1589',
        subId: 'T1589.001',
        name: 'Gather Victim Identity Information: Credentials',
        tacticId: 'TA0007',
        tacticName: 'Reconnaissance',
        description: 'Adversaries collect leaked credentials from public breach databases to execute credential stuffing or password spraying attacks.',
        adversaryUse: 'Tests leaked email and password combinations against corporate VPNs, OWA, and Okta/Azure AD portals.',
        defenderMitigation: 'M1027: Password Policies & Continuous Breached Credential Screening.'
      },
      complianceControls: [
        { framework: 'NIST_SP_800_53', frameworkLabel: 'NIST SP 800-53 Rev. 5', controlId: 'IA-5(1)', controlName: 'Password-Based Authentication Defense' },
        { framework: 'CIS_V8', frameworkLabel: 'CIS Controls v8', controlId: 'CIS Control 5.2', controlName: 'Maintain Password Security and Screen for Leaks' },
        { framework: 'PCI_DSS', frameworkLabel: 'PCI-DSS v4.0', controlId: 'Requirement 8.3.6', controlName: 'Screen Against Compromised Credential Lists' }
      ]
    });
  }

  // Calculate overall attack surface health score (0-100)
  const overallScore = Math.max(10, Math.min(100, 100 - deduction));
  let grade: EasmScanResult['grade'] = 'F';
  if (overallScore >= 92) grade = 'A+';
  else if (overallScore >= 80) grade = 'A';
  else if (overallScore >= 70) grade = 'B';
  else if (overallScore >= 60) grade = 'C';
  else if (overallScore >= 50) grade = 'D';

  const scanDurationMs = Date.now() - startTime;

  return {
    domain,
    targetUrl: `https://${domain}`,
    scannedAt: new Date().toISOString(),
    scanDurationMs,
    overallScore,
    grade,
    summary: {
      criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
      highCount: findings.filter(f => f.severity === 'HIGH').length,
      mediumCount: findings.filter(f => f.severity === 'MEDIUM').length,
      lowCount: findings.filter(f => f.severity === 'LOW').length,
      subdomainsDiscovered: subdomainAssets.length,
      certificatesFound: certs.length
    },
    dns: {
      records: dnsRecords,
      emailSecurity
    },
    subdomains: subdomainAssets,
    certificates: certs,
    httpPosture,
    whois,
    network,
    findings,
    vulnerabilities
  };
}
