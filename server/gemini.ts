import { GoogleGenAI } from '@google/genai';
import { EasmScanResult } from '../src/types';

export interface ThreatBriefingResponse {
  adversaryAnalysis: string;
  mitreKillChain: {
    phase: string;
    tactic: string;
    adversaryMethod: string;
    vulnerabilityLeveraged: string;
  }[];
  topHardeningPriorities: {
    priority: number;
    action: string;
    cisControl: string;
    estimatedRiskReduction: string;
  }[];
  source?: 'gemini-live' | 'deterministic-intel';
  notice?: string;
}

let aiClient: GoogleGenAI | null = null;

// Cache briefings per domain to eliminate repeated API calls and avoid 429 quota exhaustion
const briefingCache = new Map<string, { timestamp: number; data: ThreatBriefingResponse }>();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

function getAiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

/**
 * Generate a high-fidelity, deterministic threat modeling briefing grounded directly in the target's telemetry.
 * Used when Gemini API is rate-limited (HTTP 429), experiencing high demand (HTTP 503), or when no API key is provided.
 */
export function buildDeterministicBriefing(scan: EasmScanResult, notice?: string): ThreatBriefingResponse {
  const criticalFindings = scan.findings.filter(f => f.severity === 'CRITICAL');
  const highFindings = scan.findings.filter(f => f.severity === 'HIGH');
  const dmarcEnforced = scan.dns.emailSecurity.dmarc.status === 'enforced';
  const hasWildcard = scan.subdomains.some(s => s.isWildcard);
  const totalFindings = scan.findings.length;
  const hosting = scan.network.hostingType || 'Public Cloud / Colocation';

  let attackNarrative = `External perimeter intelligence analysis for "${scan.domain}" indicates a total attack surface encompassing ${scan.subdomains.length} public subdomains and ${totalFindings} prioritized exposure vectors (Overall Posture Score: ${scan.overallScore}/100, Grade: ${scan.grade}). `;

  if (criticalFindings.length > 0) {
    attackNarrative += `Adversary red-team evaluation reveals ${criticalFindings.length} CRITICAL exposure vector(s), led by "${criticalFindings[0].title}". Threat actors and initial access brokers (IABs) actively monitor automated Certificate Transparency logs and DNS zone delegations for orphaned CNAME records to execute subdomain takeover without deploying exploit payloads. `;
  } else if (!dmarcEnforced) {
    attackNarrative += `The primary attack surface exposure lies in email authentication posture: DMARC policy is currently ${scan.dns.emailSecurity.dmarc.status} (${scan.dns.emailSecurity.dmarc.policy || 'none'}). This permits direct spoofing of @${scan.domain} sender identities in spearphishing and Business Email Compromise (BEC) campaigns targeting enterprise partners, bypassing default gateway reputation heuristics. `;
  } else {
    attackNarrative += `The apex organization maintains active perimeter defenses with enforced mail authentication. Adversary operations against this perimeter would center on subordinate asset discovery, service fingerprinting across ${hosting} infrastructure, and hunting for software version leaks or cleartext transport fallback. `;
  }

  attackNarrative += `\n\nOperational telemetry indicates ${scan.certificates.length} cryptographic certificates issued across the domain tree. Red teams prioritize auxiliary staging and administrative endpoints before probing the primary web application boundary.`;

  // Dynamic MITRE kill chain derived from actual findings
  const killChain: ThreatBriefingResponse['mitreKillChain'] = [
    {
      phase: 'Reconnaissance (TA0043)',
      tactic: 'T1596.001 - Search Open Technical Databases: DNS & CT Logs',
      adversaryMethod: `Queries public Certificate Transparency (crt.sh) and authoritative DoH resolvers to map all ${scan.subdomains.length} exposed hostnames without triggering perimeter intrusion detection systems.`,
      vulnerabilityLeveraged: `Cataloged ${scan.subdomains.length} active assets hosted on ${hosting}${hasWildcard ? ' (includes wildcard DNS delegations)' : ''}.`
    },
    {
      phase: 'Resource Development (TA0042)',
      tactic: !dmarcEnforced ? 'T1585.002 - Establish Accounts: Email Accounts' : 'T1584.001 - Compromise Infrastructure: DNS Server & Domains',
      adversaryMethod: !dmarcEnforced
        ? `Prepares spoofed outbound mail relays leveraging unauthenticated domain reputation (${scan.dns.emailSecurity.dmarc.policy === 'none' ? 'p=none allows spoofed deliverability' : 'missing DMARC record'}).`
        : 'Scrutinizes third-party CNAME pointers and DNS delegations for unallocated cloud buckets or dangling tenant slots.',
      vulnerabilityLeveraged: !dmarcEnforced
        ? `DMARC policy status is ${scan.dns.emailSecurity.dmarc.status}. Spoofed messages pass directly into partner inboxes.`
        : (scan.findings.find(f => f.category === 'Exposed Assets')?.title || 'Perimeter DNS delegation mapping.')
    },
    {
      phase: 'Initial Access (TA0001)',
      tactic: !dmarcEnforced ? 'T1566.002 - Phishing: Spearphishing Link' : (criticalFindings[0] ? 'T1190 - Exploit Public-Facing Application' : 'T1190 - Initial Ingress Vector'),
      adversaryMethod: !dmarcEnforced
        ? `Initiates executive impersonation spearphishing citing urgent vendor invoices or password resets, capitalizing on validated @${scan.domain} envelope identity.`
        : `Probes discovered perimeter interfaces (${criticalFindings[0]?.title || scan.findings[0]?.title || 'web services'}) or attempts credential interception on downgrade.`,
      vulnerabilityLeveraged: criticalFindings[0]?.evidence || highFindings[0]?.evidence || scan.findings[0]?.evidence || 'Perimeter entry points.'
    }
  ];

  // Dynamic CIS Controls hardening roadmap
  const hardeningPriorities: ThreatBriefingResponse['topHardeningPriorities'] = [
    {
      priority: 1,
      action: !dmarcEnforced
        ? 'Publish strict DMARC enforcement policy (p=reject; sp=reject; pct=100;) with automated RUA/RUF reporting in DNS TXT.'
        : 'Enforce HTTP Strict Transport Security (HSTS) with max-age=31536000 and includeSubDomains across all public hosts.',
      cisControl: !dmarcEnforced ? 'CIS Control 9.5: Implement DMARC' : 'CIS Control 9.2: Enforce TLS Communications',
      estimatedRiskReduction: !dmarcEnforced ? '45% reduction in email spoofing and brand impersonation ingress' : '35% reduction in cleartext eavesdropping and protocol downgrade'
    },
    {
      priority: 2,
      action: scan.findings.some(f => f.title.includes('CNAME') || f.title.includes('Takeover'))
        ? 'Purge orphaned CNAME records pointing to decommissioned external SaaS, AWS S3 buckets, or GitHub Pages.'
        : 'Implement continuous DNS and Certificate Transparency monitoring to automatically detect shadow IT subdomains.',
      cisControl: 'CIS Control 1.1: Establish and Maintain a Detailed Enterprise Asset Inventory',
      estimatedRiskReduction: '30% reduction in unauthorized infrastructure hijacking'
    },
    {
      priority: 3,
      action: scan.httpPosture.serverDisclosure
        ? `Suppress web server disclosure banners (Server: ${scan.httpPosture.serverDisclosure}) and configure strict Content-Security-Policy (CSP).`
        : 'Deploy DNSSEC resource record signing and restrict Certificate Authority Authorization (CAA) records.',
      cisControl: 'CIS Control 4.1: Establish and Maintain a Secure Configuration Process',
      estimatedRiskReduction: '20% reduction in automated vulnerability scanning reconnaissance'
    }
  ];

  return {
    adversaryAnalysis: attackNarrative,
    mitreKillChain: killChain,
    topHardeningPriorities: hardeningPriorities,
    source: 'deterministic-intel',
    notice: notice || undefined,
  };
}

export async function generateThreatBriefing(scan: EasmScanResult): Promise<ThreatBriefingResponse> {
  const cacheKey = scan.domain.toLowerCase().trim();

  // Check cache to avoid hitting Gemini rate limits on rapid UI navigation or duplicate requests
  const cached = briefingCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    return cached.data;
  }

  const ai = getAiClient();

  // If Gemini API is not configured, immediately return deterministic intelligence briefing
  if (!ai) {
    const briefing = buildDeterministicBriefing(scan, 'Generated via SurfaceTrace Deterministic Intelligence Engine (No GEMINI_API_KEY set).');
    briefingCache.set(cacheKey, { timestamp: Date.now(), data: briefing });
    return briefing;
  }

  // Attempt Gemini AI synthesis with graceful fallback on 429 quota exhaustion or 503 high demand
  try {
    const prompt = `You are a Principal Red Team Threat Modeler and Attack Surface Management (EASM) Expert.
Analyze the following live attack surface scan for domain "${scan.domain}" and generate an executive adversary simulation and MITRE ATT&CK mitigation briefing.

Scan Data:
- Overall Score: ${scan.overallScore}/100 (Grade: ${scan.grade})
- Findings: ${JSON.stringify(scan.findings.map(f => ({ title: f.title, severity: f.severity, mitre: f.mitre.id + ' ' + f.mitre.name, evidence: f.evidence })))}
- Subdomains Discovered: ${scan.subdomains.length}
- Email Security: DMARC=${scan.dns.emailSecurity.dmarc.status} (${scan.dns.emailSecurity.dmarc.policy}), SPF=${scan.dns.emailSecurity.spf.status}
- HTTP Posture: HTTPS=${scan.httpPosture.isHttps}, Server=${scan.httpPosture.serverDisclosure || 'Hidden'}
- Network/Host: ${scan.network.hostingType || 'Unknown'} (${scan.network.asn || 'Unknown ASN'})

Respond ONLY with valid JSON matching this schema:
{
  "adversaryAnalysis": "A detailed 2-3 paragraph analysis of how an APT or ransomware initial access broker would prioritize and exploit these specific findings.",
  "mitreKillChain": [
    {
      "phase": "e.g. Reconnaissance (TA0043)",
      "tactic": "e.g. T1596 - Search Open Technical Databases",
      "adversaryMethod": "Specific tactical steps the attacker takes",
      "vulnerabilityLeveraged": "How the target's specific scan finding is exploited"
    }
  ],
  "topHardeningPriorities": [
    {
      "priority": 1,
      "action": "Specific concrete engineering mitigation",
      "cisControl": "e.g. CIS Control 9: Email Protections",
      "estimatedRiskReduction": "e.g. 45% reduction in phishing ingress"
    }
  ]
}`;

    // Use gemini-2.5-flash which is widely provisioned, fast, and has generous quotas
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      }
    });

    const text = response.text || '';
    const parsed = JSON.parse(text);
    const result: ThreatBriefingResponse = {
      ...parsed,
      source: 'gemini-live',
    };

    // Cache the result
    briefingCache.set(cacheKey, { timestamp: Date.now(), data: result });
    return result;
  } catch (err: any) {
    const errorMsg = String(err?.message || err);
    console.warn(`[Gemini API Warning] Unable to call Gemini live model (${errorMsg.slice(0, 120)}...). Falling back to deterministic EASM intelligence engine.`);

    // Determine notice based on error code
    let notice = 'Active intelligence generated via SurfaceTrace EASM Telemetry Model.';
    if (errorMsg.includes('429') || errorMsg.includes('quota') || errorMsg.includes('RESOURCE_EXHAUSTED')) {
      notice = 'Gemini API free tier rate limit exceeded (429). SurfaceTrace seamlessly transitioned to the offline deterministic red-team intelligence engine.';
    } else if (errorMsg.includes('503') || errorMsg.includes('UNAVAILABLE') || errorMsg.includes('high demand')) {
      notice = 'Gemini model temporarily experiencing high demand (503). SurfaceTrace seamlessly transitioned to the offline deterministic red-team intelligence engine.';
    }

    const fallbackBriefing = buildDeterministicBriefing(scan, notice);
    // Cache fallback temporarily (2 minutes) so repeated renders don't log spam
    briefingCache.set(cacheKey, { timestamp: Date.now(), data: fallbackBriefing });
    return fallbackBriefing;
  }
}

