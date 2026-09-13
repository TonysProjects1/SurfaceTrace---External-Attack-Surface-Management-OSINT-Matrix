export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface MitreTechnique {
  id: string;
  subId?: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  adversaryUse: string;
  defenderMitigation: string;
}

export interface NonCompliantResource {
  type: 'subdomain' | 'dns_record' | 'http_header' | 'certificate' | 'cookie' | 'port' | 'endpoint';
  resourceIdentifier: string;
  observedIssue: string;
  currentValue?: string;
  expectedValue?: string;
  assetUrl?: string;
}

export interface EvaluatedResource {
  type: 'subdomain' | 'dns_record' | 'http_header' | 'certificate' | 'cookie' | 'port' | 'endpoint' | 'whois';
  resourceIdentifier: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIALLY_COMPLIANT';
  evaluatedConfiguration: string;
  complianceCriteria: string;
  reperformanceSource: string;
  reperformanceCommand: string;
  assetUrl?: string;
}

export interface ComplianceControlMapping {
  framework: 'NIST_SP_800_53' | 'NIST_CSF' | 'CIS_V8' | 'ISO_27001' | 'PCI_DSS';
  frameworkLabel: string;
  controlId: string;
  controlName: string;
}

export interface SecurityFinding {
  id: string;
  title: string;
  severity: Severity;
  category: 'DNS & Email' | 'Web & Transport' | 'Exposed Assets' | 'Domain Governance' | 'Network & Cloud';
  description: string;
  evidence: string;
  remediation: string;
  mitre: MitreTechnique;
  complianceControls?: ComplianceControlMapping[];
}

export interface DnsRecord {
  type: string;
  name: string;
  data: string;
  ttl?: number;
}

export interface SubdomainAsset {
  subdomain: string;
  ip?: string;
  cname?: string;
  isWildcard?: boolean;
  status: 'active' | 'unresolved' | 'suspicious_cname' | 'ct_discovered';
  riskNote?: string;
}

export interface CertificateInfo {
  id?: number | string;
  issuer: string;
  commonName: string;
  nameValue: string;
  notBefore?: string;
  notAfter?: string;
  isExpired?: boolean;
  daysRemaining?: number;
}

export interface HttpHeaderCheck {
  header: string;
  status: 'secure' | 'warning' | 'missing' | 'leak';
  value: string | null;
  recommendation: string;
  description: string;
}

export interface EmailSecurityPosture {
  spf: {
    status: 'configured' | 'weak' | 'missing';
    rawRecord: string | null;
    mechanisms: string[];
    allFlag: string | null;
    isOverlyPermissive: boolean;
    recommendation: string;
  };
  dmarc: {
    status: 'enforced' | 'monitoring_only' | 'missing';
    rawRecord: string | null;
    policy: 'reject' | 'quarantine' | 'none' | 'missing';
    subdomainPolicy?: string;
    ruaMailto?: string;
    pct?: number;
    recommendation: string;
  };
  mx: {
    hasMx: boolean;
    records: { host: string; priority: number }[];
    providersDetected: string[];
  };
}

export interface WhoisInfo {
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  daysToExpiration?: number;
  domainAgeYears?: number;
  dnssec?: boolean;
  nameServers: string[];
  abuseContact?: string;
}

export interface NetworkInfo {
  ip: string;
  asn?: string;
  asOrganization?: string;
  country?: string;
  city?: string;
  reverseDns?: string;
  hostingType?: 'Cloudflare CDN' | 'AWS' | 'Google Cloud' | 'Microsoft Azure' | 'Fastly' | 'Akamai' | 'DigitalOcean' | 'Standard Hosting' | 'Unknown';
}

export interface BreachIncident {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath?: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
}

export interface CompromisedUrlOccurrence {
  url: string;
  occurrence: number;
  type: 'Employee' | 'Client' | 'User';
}

export interface StealerIntelligence {
  totalCredentials: number;
  totalStealersIndexed: number;
  employeesInfected: number;
  usersInfected: number;
  thirdPartiesInfected: number;
  lastEmployeeCompromised?: string;
  lastUserCompromised?: string;
  stealerFamilies: Record<string, number>;
  topCompromisedUrls: CompromisedUrlOccurrence[];
  source: string;
}

export interface GitExposureDork {
  label: string;
  category: 'Credentials' | 'Cloud Secrets' | 'Private Keys' | 'Database Config' | 'Internal URLs';
  query: string;
  searchUrl: string;
  riskDescription: string;
  severity: Severity;
}

export interface VulnerabilityBreachData {
  domain: string;
  lastQueriedAt: string;
  status: 'ANALYZED' | 'WARNING' | 'CRITICAL_RISK' | 'CLEAN';
  riskScore: number; // 0-100
  totalExposedCredentials: number;
  employeeLoginsCompromised: number;
  clientCredentialsCompromised: number;
  breachesCount: number;
  breaches: BreachIncident[];
  stealerIntel: StealerIntelligence | null;
  dorks: GitExposureDork[];
  remediationRoadmap: {
    priority: number;
    title: string;
    action: string;
    standard: string;
  }[];
}

export interface EasmScanResult {
  domain: string;
  targetUrl: string;
  scannedAt: string;
  scanDurationMs: number;
  overallScore: number; // 0-100
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    subdomainsDiscovered: number;
    certificatesFound: number;
  };
  dns: {
    records: DnsRecord[];
    emailSecurity: EmailSecurityPosture;
  };
  subdomains: SubdomainAsset[];
  certificates: CertificateInfo[];
  httpPosture: {
    urlChecked: string;
    isHttps: boolean;
    redirectsToHttps: boolean;
    statusCode: number;
    headers: HttpHeaderCheck[];
    serverDisclosure: string | null;
    xPoweredByDisclosure: string | null;
    cookiesDetected: { name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[];
  };
  whois: WhoisInfo;
  network: NetworkInfo;
  findings: SecurityFinding[];
  vulnerabilities?: VulnerabilityBreachData;
}

export interface OsintTool {
  id: string;
  name: string;
  category: 
    | 'Passive DNS & Records'
    | 'Certificate Transparency'
    | 'Attack Surface & Ports'
    | 'Code & Secret Leaks'
    | 'Cloud & Storage Buckets'
    | 'Threat Intel & Reputation'
    | 'Identity & Credential Leaks'
    | 'Technology Fingerprinting'
    | 'Domain & WHOIS Intel'
    | 'Web Archives & Historical';
  url: string;
  pricing: '100% Free' | 'Free Tier / Freemium' | 'Open Source (Self-Hosted)';
  description: string;
  enterpriseUseCases: string[];
  vulnerabilityTarget: 'Subdomains' | 'DNS' | 'Exposed Ports' | 'API Keys & Secrets' | 'Cloud Storage' | 'Email Security' | 'Software CVEs' | 'Credentials';
  mitreMapping: {
    tacticId: string;
    tacticName: string;
    techniqueId: string;
    techniqueName: string;
  };
  sampleWorkflow: string;
  tags: string[];
  leveragedBySurfaceTrace?: boolean;
  surfaceTraceIntegration?: string;
}
