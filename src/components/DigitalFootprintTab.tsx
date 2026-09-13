import React, { useState } from 'react';
import { EasmScanResult, DnsRecord, SubdomainAsset, CertificateInfo } from '../types';
import { 
  Globe, Shield, Server, Lock, AlertTriangle, CheckCircle2, 
  Search, Filter, ExternalLink, Calendar, Hash, ArrowRight, Layers,
  Download, Copy, Check, Terminal, Cpu
} from 'lucide-react';

interface DigitalFootprintTabProps {
  scan: EasmScanResult;
}

export function inferSubdomainCategory(hostname: string, cname?: string): { 
  label: string; 
  badge: string; 
  className: string; 
  isRisk: boolean 
} {
  const h = hostname.toLowerCase();
  const c = (cname || '').toLowerCase();

  if (h.includes('vpn') || h.includes('remote') || h.includes('gateway') || h.includes('pulse') || h.includes('citrix')) {
    return { 
      label: 'SSL-VPN / Remote Access Gateway', 
      badge: 'VPN / Gateway', 
      className: 'bg-purple-100 text-purple-800 dark:bg-purple-950/80 dark:text-purple-300 border-purple-300 dark:border-purple-800', 
      isRisk: true 
    };
  }
  if (h.includes('api') || h.includes('graphql') || h.includes('rest') || h.includes('microservice')) {
    return { 
      label: 'API Gateway / Microservice', 
      badge: 'API Endpoint', 
      className: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-950/80 dark:text-cyan-300 border-cyan-300 dark:border-cyan-800', 
      isRisk: false 
    };
  }
  if (h.includes('dev') || h.includes('staging') || h.includes('uat') || h.includes('test') || h.includes('qa') || h.includes('preprod')) {
    return { 
      label: 'Pre-Production / Dev Environment Leak', 
      badge: 'Dev / Staging', 
      className: 'bg-red-100 text-red-800 dark:bg-red-950/80 dark:text-red-300 border-red-300 dark:border-red-800', 
      isRisk: true 
    };
  }
  if (h.includes('admin') || h.includes('portal') || h.includes('dashboard') || h.includes('internal') || h.includes('corp') || h.includes('sso') || h.includes('auth')) {
    return { 
      label: 'Management / Corporate SSO Portal', 
      badge: 'Admin / SSO', 
      className: 'bg-amber-100 text-amber-800 dark:bg-amber-950/80 dark:text-amber-300 border-amber-300 dark:border-amber-800', 
      isRisk: true 
    };
  }
  if (h.includes('mail') || h.includes('smtp') || h.includes('webmail') || h.includes('exchange') || h.includes('outlook')) {
    return { 
      label: 'Messaging / Mail Exchanger', 
      badge: 'Mail Exchanger', 
      className: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950/80 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800', 
      isRisk: false 
    };
  }
  if (h.includes('cdn') || h.includes('static') || h.includes('assets') || h.includes('media') || h.includes('img')) {
    return { 
      label: 'Content Delivery / Static Asset', 
      badge: 'CDN / Static', 
      className: 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700', 
      isRisk: false 
    };
  }
  if (c.includes('s3') || c.includes('blob') || c.includes('cloudfront') || c.includes('azure') || c.includes('aws') || c.includes('fastly')) {
    return { 
      label: 'Cloud Hosted SaaS / Object Storage', 
      badge: 'Cloud Storage', 
      className: 'bg-sky-100 text-sky-800 dark:bg-sky-950/80 dark:text-sky-300 border-sky-300 dark:border-sky-800', 
      isRisk: false 
    };
  }
  return { 
    label: 'Standard Web Application Endpoint', 
    badge: 'Web App', 
    className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/80 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800', 
    isRisk: false 
  };
}

export const DigitalFootprintTab: React.FC<DigitalFootprintTabProps> = ({ scan }) => {
  const [dnsFilter, setDnsFilter] = useState<string>('ALL');
  const [dnsSearch, setDnsSearch] = useState<string>('');
  const [subdomainSearch, setSubdomainSearch] = useState<string>('');
  const [activeSection, setActiveSection] = useState<'subdomains' | 'dns' | 'certs' | 'whois'>('subdomains');
  const [copiedHost, setCopiedHost] = useState<string | null>(null);

  // Filter DNS
  const filteredDns = scan.dns.records.filter((rec) => {
    const matchesType = dnsFilter === 'ALL' || rec.type === dnsFilter;
    const matchesSearch = !dnsSearch || 
      rec.name.toLowerCase().includes(dnsSearch.toLowerCase()) || 
      rec.data.toLowerCase().includes(dnsSearch.toLowerCase());
    return matchesType && matchesSearch;
  });

  // Unique DNS types
  const dnsTypes = ['ALL', ...Array.from(new Set(scan.dns.records.map(r => r.type)))];

  // Filter Subdomains
  const filteredSubdomains = scan.subdomains.filter(s => 
    !subdomainSearch || 
    s.subdomain.toLowerCase().includes(subdomainSearch.toLowerCase()) ||
    (s.ip && s.ip.toLowerCase().includes(subdomainSearch.toLowerCase())) ||
    (s.cname && s.cname.toLowerCase().includes(subdomainSearch.toLowerCase()))
  );

  const exportSubdomainsCsv = () => {
    const headers = ['Subdomain', 'Status', 'Resolved IP', 'CNAME Pointer', 'Inferred Service', 'Risk Classification', 'Risk Note'];
    const rows = scan.subdomains.map(s => {
      const cat = inferSubdomainCategory(s.subdomain, s.cname);
      return [
        `"${s.subdomain}"`,
        `"${s.status}"`,
        `"${s.ip || ''}"`,
        `"${s.cname || ''}"`,
        `"${cat.label}"`,
        `"${cat.badge}"`,
        `"${(s.riskNote || '').replace(/"/g, '""')}"`
      ].join(',');
    });
    const csvContent = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Subdomain_Asset_Inventory_${scan.domain.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyHostname = (hostname: string) => {
    navigator.clipboard.writeText(hostname);
    setCopiedHost(hostname);
    setTimeout(() => setCopiedHost(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation pills */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white dark:bg-slate-900 p-2 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs transition-colors">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setActiveSection('subdomains')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeSection === 'subdomains'
                ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 font-semibold border border-blue-200 dark:border-blue-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            Subdomain Inventory ({scan.subdomains.length})
          </button>
          <button
            onClick={() => setActiveSection('dns')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeSection === 'dns'
                ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 font-semibold border border-blue-200 dark:border-blue-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            DNS Records ({scan.dns.records.length})
          </button>
          <button
            onClick={() => setActiveSection('certs')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeSection === 'certs'
                ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 font-semibold border border-blue-200 dark:border-blue-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            Certificate Transparency ({scan.certificates.length})
          </button>
          <button
            onClick={() => setActiveSection('whois')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              activeSection === 'whois'
                ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 font-semibold border border-blue-200 dark:border-blue-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            WHOIS & Routing Footprint
          </button>
        </div>

        <div className="text-xs text-slate-500 dark:text-slate-400 font-mono hidden md:block">
          Asset Target: <span className="text-slate-900 dark:text-white font-semibold">{scan.domain}</span>
        </div>
      </div>

      {/* SECTION 1: SUBDOMAIN ASSET INVENTORY */}
      {activeSection === 'subdomains' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                Discovered Subdomain Surface & Cloud Pointers
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Enumerated from Certificate Transparency logs, passive datasets, and active DNS resolution
              </p>
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                onClick={exportSubdomainsCsv}
                className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer shrink-0"
                title="Export asset inventory to CSV"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV ({scan.subdomains.length})</span>
              </button>

              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-400" />
                <input
                  type="text"
                  value={subdomainSearch}
                  onChange={(e) => setSubdomainSearch(e.target.value)}
                  placeholder="Search subdomains, IPs, CNAMEs..."
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-xs font-mono text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:bg-white dark:focus:bg-slate-950 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300 uppercase font-semibold tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-4">Subdomain Hostname</th>
                  <th className="py-3 px-4">Inferred Service Role</th>
                  <th className="py-3 px-4">Resolution Status</th>
                  <th className="py-3 px-4">Resolved IP</th>
                  <th className="py-3 px-4">CNAME Pointer</th>
                  <th className="py-3 px-4">Attack Surface Risk Note</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
                {filteredSubdomains.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No subdomains matching filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredSubdomains.map((sub, idx) => {
                    const cat = inferSubdomainCategory(sub.subdomain, sub.cname);
                    return (
                      <tr key={idx} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4 text-slate-900 dark:text-slate-100 font-semibold">
                          <div className="flex items-center gap-2">
                            <span className="text-blue-600 dark:text-blue-400 truncate max-w-xs">{sub.subdomain}</span>
                            <button
                              onClick={() => copyHostname(sub.subdomain)}
                              className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                              title="Copy subdomain"
                            >
                              {copiedHost === sub.subdomain ? (
                                <Check className="w-3 h-3 text-emerald-500" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                            {sub.isWildcard && (
                              <span className="px-1.5 py-0.2 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 text-[10px] border border-amber-200 dark:border-amber-800 font-sans font-medium">
                                Wildcard
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-semibold border ${cat.className} inline-flex items-center gap-1`}>
                            {cat.badge}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {sub.status === 'active' ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-medium inline-flex items-center gap-1 font-sans">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Active Host
                            </span>
                          ) : sub.status === 'suspicious_cname' ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 font-semibold inline-flex items-center gap-1 font-sans animate-pulse">
                              <AlertTriangle className="w-3 h-3 text-red-600 dark:text-red-400" /> Dangling Takeover Risk
                            </span>
                          ) : sub.status === 'unresolved' ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-medium font-sans">
                              CNAME Only
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-medium font-sans">
                              CT Discovered
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-700 dark:text-slate-300">
                          {sub.ip ? (
                            <span className="bg-slate-100 dark:bg-slate-950 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200">
                              {sub.ip}
                            </span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400 truncate max-w-xs">
                          {sub.cname ? (
                            <span className="text-amber-700 dark:text-amber-300 font-mono text-[11px]">
                              {sub.cname}
                            </span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {sub.riskNote ? (
                            <span className={`text-[11px] font-sans ${sub.status === 'suspicious_cname' ? 'text-red-700 dark:text-red-400 font-semibold' : 'text-slate-600 dark:text-slate-400'}`}>
                              {sub.riskNote}
                            </span>
                          ) : (
                            <span className="text-slate-400 font-sans">Standard zone resolution</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SECTION 2: DNS RECORDS EXPLORER */}
      {activeSection === 'dns' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Hash className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                Live DNS Zone Records (DoH Resolution)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Authoritative zone records queried via DNS over HTTPS resolvers
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-950 p-1 rounded-lg border border-slate-200 dark:border-slate-800">
                <Filter className="w-3 h-3 text-slate-400 ml-1" />
                {dnsTypes.map(type => (
                  <button
                    key={type}
                    onClick={() => setDnsFilter(type)}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer ${
                      dnsFilter === type
                        ? 'bg-white dark:bg-slate-700 text-blue-700 dark:text-blue-300 font-bold shadow-xs border border-slate-200 dark:border-slate-600'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>

              <div className="relative flex-1 sm:w-48">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  value={dnsSearch}
                  onChange={(e) => setDnsSearch(e.target.value)}
                  placeholder="Search records..."
                  className="w-full pl-9 pr-3 py-1 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg text-xs font-mono text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:bg-white dark:focus:bg-slate-950 focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600"
                />
              </div>
            </div>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300 uppercase tracking-wider font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Name / Host</th>
                  <th className="py-3 px-4">Data / Value</th>
                  <th className="py-3 px-4">TTL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {filteredDns.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-slate-500">
                      No DNS records found matching criteria.
                    </td>
                  </tr>
                ) : (
                  filteredDns.map((rec, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          rec.type === 'A' || rec.type === 'AAAA' ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800' :
                          rec.type === 'MX' ? 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800' :
                          rec.type === 'TXT' ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800' :
                          rec.type === 'CAA' ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800' :
                          'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700'
                        }`}>
                          {rec.type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-800 dark:text-slate-200 font-semibold">{rec.name}</td>
                      <td className="py-3 px-4 text-slate-700 dark:text-slate-300 break-all max-w-xl">
                        {rec.data}
                      </td>
                      <td className="py-3 px-4 text-slate-500">{rec.ttl || 300}s</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SECTION 3: CERTIFICATE TRANSPARENCY (CT) */}
      {activeSection === 'certs' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Certificate Transparency (CT) Log Intelligence
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Cryptographic certificates issued to this domain indexed by public Certificate Authorities
            </p>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300 uppercase tracking-wider font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-4">Certificate Issuer</th>
                  <th className="py-3 px-4">Common Name</th>
                  <th className="py-3 px-4">Valid Range</th>
                  <th className="py-3 px-4">Expiry Status</th>
                  <th className="py-3 px-4">Identified SANs</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {scan.certificates.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      No public certificates retrieved from CT log mirrors.
                    </td>
                  </tr>
                ) : (
                  scan.certificates.map((cert, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 text-slate-800 dark:text-slate-200 font-semibold">{cert.issuer}</td>
                      <td className="py-3 px-4 text-blue-600 dark:text-blue-400">{cert.commonName}</td>
                      <td className="py-3 px-4 text-slate-500 dark:text-slate-400 text-[11px]">
                        {cert.notBefore ? new Date(cert.notBefore).toLocaleDateString() : 'N/A'} → {cert.notAfter ? new Date(cert.notAfter).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="py-3 px-4">
                        {cert.isExpired ? (
                          <span className="px-2 py-0.5 rounded bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 text-[10px] font-bold">
                            Expired
                          </span>
                        ) : cert.daysRemaining !== undefined && cert.daysRemaining < 30 ? (
                          <span className="px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 text-[10px] font-bold">
                            Expiring soon ({cert.daysRemaining}d)
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 text-[10px] font-bold">
                            Valid ({cert.daysRemaining || 90}d remaining)
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300 text-[11px] truncate max-w-xs">
                        {cert.nameValue}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SECTION 4: WHOIS & ROUTING */}
      {activeSection === 'whois' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Domain Registration & RDAP */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <Shield className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Domain Registration & Governance (RDAP)
            </h2>
            <div className="space-y-3 text-xs font-mono">
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Registrar:</span>
                <span className="text-slate-900 dark:text-white font-semibold">{scan.whois.registrar || 'Public Registrar'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Registration Date:</span>
                <span className="text-slate-800 dark:text-slate-200">
                  {scan.whois.creationDate ? new Date(scan.whois.creationDate).toLocaleDateString() : 'N/A'}
                  {scan.whois.domainAgeYears !== undefined && ` (${scan.whois.domainAgeYears} years old)`}
                </span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Expiration Date:</span>
                <span className="text-slate-800 dark:text-slate-200">
                  {scan.whois.expirationDate ? new Date(scan.whois.expirationDate).toLocaleDateString() : 'N/A'}
                  {scan.whois.daysToExpiration !== undefined && ` (${scan.whois.daysToExpiration} days left)`}
                </span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">DNSSEC Protection:</span>
                <span className={scan.whois.dnssec ? 'text-emerald-700 dark:text-emerald-400 font-semibold' : 'text-amber-700 dark:text-amber-400 font-semibold'}>
                  {scan.whois.dnssec ? 'Signed & Active (DNSSEC)' : 'Unsigned / Inactive'}
                </span>
              </div>
              <div className="py-2">
                <span className="text-slate-500 dark:text-slate-400 block mb-1">Authoritative Name Servers:</span>
                <div className="space-y-1">
                  {scan.whois.nameServers.length > 0 ? (
                    scan.whois.nameServers.map((ns, i) => (
                      <div key={i} className="text-slate-800 dark:text-slate-200 bg-slate-50 dark:bg-slate-950 px-2.5 py-1.5 rounded-md border border-slate-200 dark:border-slate-800">
                        {ns}
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-400">Querying DoH NS records...</div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Autonomous System & Network Infrastructure */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <Server className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Routing & Autonomous System Footprint
            </h2>
            <div className="space-y-3 text-xs font-mono">
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Primary IP Address:</span>
                <span className="text-slate-900 dark:text-white font-semibold">{scan.network.ip || 'No A record'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Autonomous System (ASN):</span>
                <span className="text-blue-600 dark:text-blue-400 font-semibold">{scan.network.asn || 'Private / Unannounced'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">AS Organization / ISP:</span>
                <span className="text-slate-800 dark:text-slate-200">{scan.network.asOrganization || 'Global CDN Gateway'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Geographic Origin:</span>
                <span className="text-slate-800 dark:text-slate-200">
                  {scan.network.city ? `${scan.network.city}, ` : ''}{scan.network.country || 'Distributed Edge'}
                </span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Hosting / Cloud Tier:</span>
                <span className="text-emerald-700 dark:text-emerald-400 font-semibold">{scan.network.hostingType || 'Standard Cloud'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-slate-500 dark:text-slate-400">Reverse PTR:</span>
                <span className="text-slate-600 dark:text-slate-300 truncate max-w-xs">{scan.network.reverseDns || 'No reverse pointer'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
