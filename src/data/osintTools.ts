import { OsintTool } from '../types';

export const OSINT_TOOLS: OsintTool[] = [
  {
    id: 'crt-sh',
    name: 'crt.sh (Certificate Transparency Log Search)',
    category: 'Certificate Transparency',
    url: 'https://crt.sh',
    pricing: '100% Free',
    description: 'A publicly searchable interface to the Certificate Transparency (CT) logs maintained by Sectigo. It indexes every cryptographic TLS/SSL certificate issued by publicly trusted Certificate Authorities worldwide.',
    enterpriseUseCases: [
      'Uncovering hidden, forgotten, or undocumented subdomains (e.g. dev-internal.company.com, staging-auth.company.com).',
      'Detecting shadow IT deployments where developers registered new public domains or subdomains with Let\'s Encrypt.',
      'Auditing wildcard certificates that might expand vulnerability blast radius across unrelated clusters.',
      'Spotting unauthorized or rogue certificate issuances before malicious lookalike domains are weaponized.'
    ],
    vulnerabilityTarget: 'Subdomains',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596.003',
      techniqueName: 'Search Open Technical Databases: Digital Certificates'
    },
    sampleWorkflow: 'Query "%.targetcompany.com" to retrieve all historic and current subdomains extracted from Subject Alternative Names (SANs).',
    tags: ['CT Logs', 'Subdomains', 'SSL/TLS', 'Passive Recon']
  },
  {
    id: 'dnsdumpster',
    name: 'DNSDumpster',
    category: 'Passive DNS & Records',
    url: 'https://dnsdumpster.com',
    pricing: '100% Free',
    description: 'A completely free domain research tool that discovers hosts, subdomains, DNS records (A, MX, NS, TXT), and draws an interactive graphical representation of an organization\'s network perimeter.',
    enterpriseUseCases: [
      'Visualizing the external network perimeter topology to identify perimeter boundary gaps.',
      'Auditing outdated MX and DNS servers that are no longer patched.',
      'Detecting dangling CNAME records pointing to decommissioned third-party cloud providers (AWS S3, Heroku, Azure) ripe for subdomain takeover.'
    ],
    vulnerabilityTarget: 'DNS',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596.001',
      techniqueName: 'Search Open Technical Databases: DNS Records'
    },
    sampleWorkflow: 'Input company root domain to pull complete zone data, map MX records to mail gateways, and locate forgotten test environments.',
    tags: ['DNS', 'Perimeter Mapping', 'Topology', 'Visual Recon']
  },
  {
    id: 'shodan',
    name: 'Shodan Search Engine',
    category: 'Attack Surface & Ports',
    url: 'https://www.shodan.io',
    pricing: 'Free Tier / Freemium',
    description: 'The world\'s premier search engine for Internet-connected devices. Continuously scans the entire IPv4 address space and common IPv6 ranges, indexing open ports, service banners, TLS configurations, and default device logins.',
    enterpriseUseCases: [
      'Detecting exposed administrative interfaces (RDP port 3389, SSH 22, Telnet 23, VNC 5900, phpMyAdmin).',
      'Discovering exposed unauthenticated databases (Elasticsearch 9200, MongoDB 27017, Redis 6379) holding sensitive enterprise data.',
      'Monitoring newly provisioned corporate IP blocks for unexpected public services before attackers scan them.'
    ],
    vulnerabilityTarget: 'Exposed Ports',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1595.002',
      techniqueName: 'Active Scanning: Vulnerability Scanning'
    },
    sampleWorkflow: 'Search "org:\\"Target Enterprise\\" port:9200,27017" or "ssl:\\"targetcompany.com\\"" to discover exposed backend endpoints.',
    tags: ['IoT', 'Port Scanning', 'Exposed Services', 'Service Banners']
  },
  {
    id: 'censys-search',
    name: 'Censys Search',
    category: 'Attack Surface & Ports',
    url: 'https://search.censys.io',
    pricing: 'Free Tier / Freemium',
    description: 'An authoritative public scanner and search engine founded by researchers at the University of Michigan. Provides structured telemetry on global IP addresses, virtual hosts, and TLS certificates.',
    enterpriseUseCases: [
      'Uncovering origin IP addresses hidden behind reverse-proxy Web Application Firewalls (Cloudflare, Akamai) by matching TLS certificates.',
      'Auditing cryptographic weakness (SSLv3, TLS 1.0/1.1, expired certs, self-signed test certs).',
      'Querying specific software versions across corporate infrastructure to identify unpatched zero-day exposure.'
    ],
    vulnerabilityTarget: 'Exposed Ports',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596.005',
      techniqueName: 'Search Open Technical Databases: Scan Databases'
    },
    sampleWorkflow: 'Run `services.tls.certificates.leaf_data.names: targetcompany.com` to discover IP addresses presenting your corporate SSL cert without CDN protection.',
    tags: ['Origin Discovery', 'TLS Auditing', 'Virtual Hosts', 'WAF Bypass']
  },
  {
    id: 'grayhatwarfare',
    name: 'GrayhatWarfare (Public Cloud Bucket Search)',
    category: 'Cloud & Storage Buckets',
    url: 'https://grayhatwarfare.com',
    pricing: 'Free Tier / Freemium',
    description: 'A searchable database of over 100,000 public Amazon AWS S3 buckets, Microsoft Azure Blobs, and Google Cloud Storage buckets containing hundreds of millions of exposed files.',
    enterpriseUseCases: [
      'Detecting leaked corporate databases, SQL backups (.bak, .sql), and database dumps accidentally left readable to "AllUsers".',
      'Finding exposed employee PII, internal invoices, HR records, and proprietary engineering spreadsheets.',
      'Checking if third-party contractors configured leaky buckets bearing the enterprise brand name.'
    ],
    vulnerabilityTarget: 'Cloud Storage',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1593.001',
      techniqueName: 'Search Open Websites/Domains: Social Media / Cloud Storage'
    },
    sampleWorkflow: 'Search keywords like "targetcompany backup", "targetcompany-prod", or "targetcompany.com" to audit exposed object storage.',
    tags: ['AWS S3', 'Azure Blob', 'Cloud Leak', 'Data Exposure']
  },
  {
    id: 'gitguardian-public',
    name: 'GitGuardian Public Monitoring & HasMySecretLeaked',
    category: 'Code & Secret Leaks',
    url: 'https://www.gitguardian.com/hasmysecretleaked',
    pricing: '100% Free',
    description: 'An automated engine scanning millions of public GitHub and GitLab repositories in real-time, matching against 400+ secret types including AWS IAM keys, private RSA keys, and Stripe tokens.',
    enterpriseUseCases: [
      'Verifying if company API tokens or developer credentials were leaked into public personal repos.',
      'Identifying hardcoded database connection strings containing administrative passwords.',
      'Stopping credential reuse attacks before initial access brokers harvest exposed secrets from commit logs.'
    ],
    vulnerabilityTarget: 'API Keys & Secrets',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1593.003',
      techniqueName: 'Search Open Websites/Domains: Code Repositories'
    },
    sampleWorkflow: 'Query organizational domain and token hashes via HasMySecretLeaked to check if employee commits exposed cloud infrastructure keys.',
    tags: ['GitHub', 'Secret Leaks', 'API Keys', 'Credentials']
  },
  {
    id: 'haveibeenpwned',
    name: 'Have I Been Pwned (HIBP)',
    category: 'Identity & Credential Leaks',
    url: 'https://haveibeenpwned.com',
    pricing: '100% Free',
    description: 'Troy Hunt\'s authoritative database indexing billions of breached accounts from corporate leaks, stealer logs, and credential dumps, allowing domain-level auditing of compromised corporate emails.',
    enterpriseUseCases: [
      'Domain search to identify executive and employee email addresses compromised in external breaches.',
      'Pinpointing high-risk employees likely targeted for credential stuffing against enterprise SSO/VPN portals.',
      'Enforcing mandatory password resets and MFA policies on compromised accounts.'
    ],
    vulnerabilityTarget: 'Credentials',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1589.001',
      techniqueName: 'Gather Victim Identity Information: Credentials'
    },
    sampleWorkflow: 'Use the domain verification tool to generate a report of all `@company.com` addresses present in historical database breaches.',
    tags: ['Credential Stuffing', 'Breaches', 'Identity', 'Password Auditing']
  },
  {
    id: 'securitytrails',
    name: 'SecurityTrails (Historical DNS & WHOIS)',
    category: 'Passive DNS & Records',
    url: 'https://securitytrails.com',
    pricing: 'Free Tier / Freemium',
    description: 'Massive passive DNS dataset containing billions of historical DNS records, past IP assignments, nameserver histories, and domain ownership records dating back over a decade.',
    enterpriseUseCases: [
      'Tracing previous IP addresses to discover unpatched legacy servers that still respond even after modern CDN migration.',
      'Investigating domain lineage to reveal past infrastructure providers and forgotten hosting accounts.',
      'Correlating shared historical MX or NS records to map out subsidiary corporations and merged acquisitions.'
    ],
    vulnerabilityTarget: 'DNS',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596.001',
      techniqueName: 'Search Open Technical Databases: DNS Records'
    },
    sampleWorkflow: 'Inspect historical A records for "api.company.com" to identify past bare-metal IPs that remain active and vulnerable to direct attacks.',
    tags: ['Historical DNS', 'Passive DNS', 'Legacy Assets', 'Domain History']
  },
  {
    id: 'wayback-machine',
    name: 'Internet Archive: Wayback Machine',
    category: 'Web Archives & Historical',
    url: 'https://web.archive.org',
    pricing: '100% Free',
    description: 'A digital library preserving historical snapshots of websites over decades. Indexes old HTML pages, linked JavaScript bundles, configuration files, and deprecated API endpoints.',
    enterpriseUseCases: [
      'Discovering deprecated API endpoints, forgotten admin login URLs, and historical documentation files.',
      'Extracting hardcoded API keys and internal staging URLs from archived JavaScript client-side bundles (e.g. `main.chunk.js`).',
      'Detecting removed disclosures or legal notices that leak infrastructure architecture details.'
    ],
    vulnerabilityTarget: 'Software CVEs',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1593.002',
      techniqueName: 'Search Open Websites/Domains: Search Engines'
    },
    sampleWorkflow: 'Query `https://web.archive.org/cdx/search/cdx?url=*.targetcompany.com/*&output=json&fl=original&collapse=urlkey` to dump all historic URLs and endpoints.',
    tags: ['Web Archive', 'Historical Endpoints', 'JavaScript Recon', 'Deprecated APIs']
  },
  {
    id: 'wappalyzer',
    name: 'Wappalyzer (Technology Profiler)',
    category: 'Technology Fingerprinting',
    url: 'https://www.wappalyzer.com',
    pricing: 'Free Tier / Freemium',
    description: 'A cross-platform utility and extension that identifies software, web frameworks, CMS platforms, e-commerce engines, analytics tools, server technologies, and JavaScript libraries powering websites.',
    enterpriseUseCases: [
      'Fingerprinting outdated web frameworks (e.g. vulnerable versions of Apache Struts, Log4j, outdated WordPress plugins).',
      'Cataloging disparate web technologies across thousands of decentralized marketing microsites.',
      'Identifying vulnerable third-party JavaScript libraries (e.g. ancient jQuery versions susceptible to XSS).'
    ],
    vulnerabilityTarget: 'Software CVEs',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1592.002',
      techniqueName: 'Gather Victim Host Information: Software'
    },
    sampleWorkflow: 'Analyze public web assets to build an inventory of deployed web servers (Nginx vs IIS), server-side language versions (PHP 7.x vs 8.x), and CMS installations.',
    tags: ['Tech Stack', 'Fingerprinting', 'CMS', 'Software Versions']
  },
  {
    id: 'cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV) Catalog',
    category: 'Threat Intel & Reputation',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    pricing: '100% Free',
    description: 'The authoritative, continuously updated catalog maintained by the U.S. Cybersecurity and Infrastructure Security Agency (CISA) detailing CVEs actively weaponized by adversaries in the wild.',
    enterpriseUseCases: [
      'Prioritizing remediation: comparing external internet-facing software versions directly against CVEs with active exploits.',
      'Mandating emergency patching for perimeter assets (VPN gateways, Citrix ADC, Fortinet, Ivanti, MOVEit).',
      'Aligning vulnerability management SLAs with empirical adversary activity rather than raw theoretical CVSS scores.'
    ],
    vulnerabilityTarget: 'Software CVEs',
    mitreMapping: {
      tacticId: 'TA0001',
      tacticName: 'Initial Access',
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application'
    },
    sampleWorkflow: 'Cross-reference perimeter service versions discovered via Shodan/Censys against the KEV API to immediately isolate weaponized vectors.',
    tags: ['CISA KEV', 'Zero-Days', 'Active Exploits', 'Perimeter Defense']
  },
  {
    id: 'greynoise',
    name: 'GreyNoise Visualizer & Trends',
    category: 'Threat Intel & Reputation',
    url: 'https://viz.greynoise.io',
    pricing: 'Free Tier / Freemium',
    description: 'Analyzes global internet background noise, mass scanners, benign research bots, and active malicious botnets targeting enterprise perimeter devices in real time.',
    enterpriseUseCases: [
      'Distinguishing between benign internet noise (censys, shodan) and targeted adversary reconnaissance.',
      'Discovering if enterprise perimeter IPs are participating in unauthorized outbound scanning or infected by botnets.',
      'Verifying if specific CVE exploit attempts hitting your perimeter are widespread opportunistic spam or targeted attacks.'
    ],
    vulnerabilityTarget: 'Exposed Ports',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1595.001',
      techniqueName: 'Active Scanning: Scanning IP Blocks'
    },
    sampleWorkflow: 'Enter external corporate gateway IPs into GreyNoise to ensure corporate devices are not flagged as malicious actors or scanner relays.',
    tags: ['Internet Noise', 'Botnets', 'Threat Feeds', 'Perimeter Scanners']
  },
  {
    id: 'bgpview',
    name: 'BGPView & Hurricane Electric BGP Toolkit',
    category: 'Domain & WHOIS Intel',
    url: 'https://bgpview.io',
    pricing: '100% Free',
    description: 'Comprehensive BGP and routing analysis engine providing visibility into Autonomous System Numbers (ASNs), IPv4/IPv6 prefixes, peering relationships, and upstream transit providers.',
    enterpriseUseCases: [
      'Mapping all CIDR IP blocks officially owned or announced by an enterprise conglomerate.',
      'Detecting rogue or accidental BGP route leaks and prefix hijacks that reroute corporate traffic.',
      'Identifying unmonitored subsidiary network blocks that bypass corporate SOC visibility.'
    ],
    vulnerabilityTarget: 'DNS',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1590.005',
      techniqueName: 'Gather Victim Network Information: IP Addresses'
    },
    sampleWorkflow: 'Search enterprise name to retrieve registered ASN numbers (e.g. AS13335) and enumerate all announced IP prefixes to define full attack surface scope.',
    tags: ['BGP', 'ASN', 'CIDR Blocks', 'Routing Intelligence']
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    category: 'Threat Intel & Reputation',
    url: 'https://www.abuseipdb.com',
    pricing: 'Free Tier / Freemium',
    description: 'A crowdsourced IP address reputation database where system administrators report malicious IPs involved in brute-forcing, spamming, port scanning, and DDoS attacks.',
    enterpriseUseCases: [
      'Verifying whether enterprise public-facing IP addresses have been reported for abusive or compromised behavior.',
      'Investigating whether shared cloud IP addresses assigned to company workloads have toxic historical reputations.',
      'Automating reputation scoring of inbound reconnaissance probes.'
    ],
    vulnerabilityTarget: 'Exposed Ports',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1590.005',
      techniqueName: 'Gather Victim Network Information: IP Addresses'
    },
    sampleWorkflow: 'Input company mail servers and VPN gateways to confirm clean abuse confidence scores and avoid transactional email blacklisting.',
    tags: ['IP Reputation', 'Abuse Database', 'Blacklist Checks', 'Brute Force']
  },
  {
    id: 'dmarcian-inspector',
    name: 'DMARCian DMARC & SPF Inspector',
    category: 'Domain & WHOIS Intel',
    url: 'https://dmarcian.com/dmarc-inspector',
    pricing: '100% Free',
    description: 'Specialized email security inspection tool designed to diagnose and validate SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC deployment policies.',
    enterpriseUseCases: [
      'Detecting lack of DMARC enforcement (e.g. p=none policy), allowing adversaries to spoof company executives in CEO fraud / business email compromise (BEC).',
      'Identifying SPF records exceeding the 10 DNS lookup limit, causing legitimate mail delivery failures and authentication fallbacks.',
      'Flagging overly permissive SPF mechanisms such as `+all` or broad IP ranges (`include:spf.protection.outlook.com ~all`).'
    ],
    vulnerabilityTarget: 'Email Security',
    mitreMapping: {
      tacticId: 'TA0001',
      tacticName: 'Initial Access',
      techniqueId: 'T1566.002',
      techniqueName: 'Phishing: Spearphishing Link / Domain Spoofing'
    },
    sampleWorkflow: 'Inspect root and subdomains to verify strict DMARC enforcement `p=reject` with comprehensive `rua` telemetry reporting.',
    tags: ['DMARC', 'SPF', 'Email Spoofing', 'Phishing Defense']
  },
  {
    id: 'can-i-take-over-xyz',
    name: 'Can I Take Over XYZ (Subdomain Takeover Knowledgebase)',
    category: 'Passive DNS & Records',
    url: 'https://github.com/EdOverflow/can-i-take-over-xyz',
    pricing: '100% Free',
    description: 'An authoritative open-source reference guide tracking which cloud providers, hosting services, and CDNs are vulnerable to subdomain takeover when CNAME records dangle.',
    enterpriseUseCases: [
      'Cross-referencing dangling CNAME records (e.g. pointers to GitHub Pages, Heroku, AWS S3, Zendesk, Shopify, Fastly, Azure Traffic Manager) against known fingerprint signatures.',
      'Remediating dangling subdomains before hostile actors claim the backend resource and host phishing portals with valid enterprise SSL certs.',
      'Securing corporate cookies: preventing attackers from harvesting scoped session cookies on root domains via hijacked subdomains.'
    ],
    vulnerabilityTarget: 'Subdomains',
    mitreMapping: {
      tacticId: 'TA0042',
      tacticName: 'Resource Development',
      techniqueId: 'T1584.004',
      techniqueName: 'Compromise Infrastructure: Server Hijacking'
    },
    sampleWorkflow: 'Identify CNAME records returning NXDOMAIN or provider 404 error pages, match against provider entries, and immediately delete the DNS record.',
    tags: ['Subdomain Takeover', 'Dangling CNAME', 'Cloud Hijack', 'DNS Hygiene']
  },
  {
    id: 'project-discovery-subfinder',
    name: 'ProjectDiscovery Subfinder & Chaos',
    category: 'Certificate Transparency',
    url: 'https://chaos.projectdiscovery.io',
    pricing: '100% Free',
    description: 'A high-speed passive reconnaissance platform and dataset indexing billions of verified subdomains across the internet using over 40 passive OSINT sources without touching target servers.',
    enterpriseUseCases: [
      'Comprehensive passive asset discovery that generates zero active network traffic or logs on the target perimeter.',
      'Continuous attack surface delta monitoring: detecting when newly created subdomains enter public datasets.',
      'Rapid benchmarking of corporate perimeter breadth across distributed multi-cloud footprints.'
    ],
    vulnerabilityTarget: 'Subdomains',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596.001',
      techniqueName: 'Search Open Technical Databases: DNS Records'
    },
    sampleWorkflow: 'Download Chaos dataset or run passive Subfinder against target domains to map out complete secondary and tertiary subdomains.',
    tags: ['Subdomains', 'Passive Discovery', 'Fast Enumeration', 'Asset Discovery']
  },
  {
    id: 'virustotal',
    name: 'VirusTotal Graph & Domain Intelligence',
    category: 'Threat Intel & Reputation',
    url: 'https://www.virustotal.com',
    pricing: 'Free Tier / Freemium',
    description: 'Google Chronicle\'s premier malware and threat analysis platform. Provides rich domain telemetry including passive DNS resolutions, communicating malware samples, URL detections, and whois data.',
    enterpriseUseCases: [
      'Checking whether enterprise subdomains have been hijacked or infected to host malware downloaders.',
      'Auditing relationships between corporate domains and known command-and-control (C2) infrastructure.',
      'Evaluating whether corporate domains are blacklisted by major browser vendors (Google Safe Browsing, Microsoft SmartScreen).'
    ],
    vulnerabilityTarget: 'DNS',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1596',
      techniqueName: 'Search Open Technical Databases'
    },
    sampleWorkflow: 'Enter target domain to inspect VirusTotal relations graph: identify communicating files, detected URLs, and sibling domains sharing IPs.',
    tags: ['Malware', 'Domain Reputation', 'Safe Browsing', 'Graph Intel']
  },
  {
    id: 'robtex',
    name: 'Robtex IP & Domain Swiss Army Knife',
    category: 'Passive DNS & Records',
    url: 'https://www.robtex.com',
    pricing: '100% Free',
    description: 'A classic internet research tool providing deep passive DNS, shared hosting records, reverse DNS lookups, Autonomous System graphs, and routing paths.',
    enterpriseUseCases: [
      'Finding "neighbor" domains hosted on the same shared IP addresses (shared hosting risk analysis).',
      'Verifying mail server configurations and reverse PTR records to ensure anti-spoofing validity.',
      'Auditing external DNS authority delegation.'
    ],
    vulnerabilityTarget: 'DNS',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1590.002',
      techniqueName: 'Gather Victim Network Information: DNS'
    },
    sampleWorkflow: 'Run reverse IP lookups to discover all other websites co-hosted on your server, preventing lateral risk from adjacent compromised sites.',
    tags: ['Reverse DNS', 'Shared Hosting', 'Network Graph', 'DNS Graph']
  },
  {
    id: 'securityheaders',
    name: 'SecurityHeaders.com',
    category: 'Technology Fingerprinting',
    url: 'https://securityheaders.com',
    pricing: '100% Free',
    description: 'Created by security researcher Scott Helme to assess HTTP response headers for defensive security best practices and compliance.',
    enterpriseUseCases: [
      'Detecting missing Content-Security-Policy (CSP) headers, exposing web applications to cross-site scripting (XSS) and data exfiltration.',
      'Checking for absent Strict-Transport-Security (HSTS) headers, enabling SSL-stripping man-in-the-middle attacks.',
      'Auditing X-Frame-Options to prevent UI redressing and clickjacking on authentication panels.'
    ],
    vulnerabilityTarget: 'Software CVEs',
    mitreMapping: {
      tacticId: 'TA0043',
      tacticName: 'Reconnaissance',
      techniqueId: 'T1592.004',
      techniqueName: 'Gather Victim Host Information: Client Configurations'
    },
    sampleWorkflow: 'Audit all company web portals to enforce mandatory HSTS preloading, robust CSP nonces, and `X-Content-Type-Options: nosniff`.',
    tags: ['HTTP Headers', 'HSTS', 'CSP', 'Clickjacking Defense']
  }
];

export const MITRE_TACTIC_LIST = [
  {
    id: 'TA0043',
    name: 'Reconnaissance',
    description: 'The adversary is trying to gather information they can use to plan future operations.',
    color: 'border-cyan-500 text-cyan-400 bg-cyan-950/40',
    badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
  },
  {
    id: 'TA0042',
    name: 'Resource Development',
    description: 'The adversary is trying to establish resources they can use to support operations.',
    color: 'border-amber-500 text-amber-400 bg-amber-950/40',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/30'
  },
  {
    id: 'TA0001',
    name: 'Initial Access',
    description: 'The adversary is trying to get into your network through public-facing assets.',
    color: 'border-rose-500 text-rose-400 bg-rose-950/40',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/30'
  }
];
