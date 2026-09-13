import React, { useState } from 'react';
import { EasmScanResult } from '../types';
import { 
  evaluateCompliancePosture, 
  ComplianceFramework, 
  ComplianceStatus, 
  FullComplianceAuditReport,
  ComplianceControlCheck 
} from '../utils/complianceEngine';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, 
  FileText, Download, Copy, Check, ExternalLink, Filter,
  ChevronDown, ChevronRight, Award, Layers, Scale, Sparkles,
  Info, ArrowDown, BookOpen, AlertOctagon, Globe, Key, Lock, Cookie, Server,
  Terminal, CheckCircle, XCircle
} from 'lucide-react';

interface ComplianceReportTabProps {
  scan: EasmScanResult;
}

const STATUS_CONFIG: Record<ComplianceStatus, { label: string; badgeClass: string; icon: React.ReactNode }> = {
  COMPLIANT: {
    label: 'COMPLIANT',
    badgeClass: 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800',
    icon: <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
  },
  PARTIALLY_COMPLIANT: {
    label: 'PARTIAL',
    badgeClass: 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800',
    icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
  },
  NON_COMPLIANT: {
    label: 'NON-COMPLIANT',
    badgeClass: 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800',
    icon: <ShieldAlert className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
  },
  AUDIT_FLAGGED: {
    label: 'AUDIT FLAGGED',
    badgeClass: 'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800',
    icon: <AlertTriangle className="w-3.5 h-3.5 text-orange-600 dark:text-orange-400" />
  }
};

export const ComplianceReportTab: React.FC<ComplianceReportTabProps> = ({ scan }) => {
  const [activeFrameworkFilter, setActiveFrameworkFilter] = useState<ComplianceFramework | 'ALL'>('ALL');
  const [activeStatusFilter, setActiveStatusFilter] = useState<ComplianceStatus | 'ALL'>('ALL');
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);
  const [copiedBriefing, setCopiedBriefing] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const report: FullComplianceAuditReport = evaluateCompliancePosture(scan);

  const filteredChecks = report.checks.filter(c => {
    const matchesFw = activeFrameworkFilter === 'ALL' || c.framework === activeFrameworkFilter;
    const matchesStatus = activeStatusFilter === 'ALL' || c.status === activeStatusFilter;
    return matchesFw && matchesStatus;
  });

  const handleCopyCommand = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCommand(id);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const getRatingBadge = (rating: 'PASS' | 'CONDITIONAL_PASS' | 'HIGH_RISK_FAIL') => {
    switch (rating) {
      case 'PASS':
        return (
          <span className="px-3 py-1 rounded-full bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-200 border border-emerald-300 dark:border-emerald-800 font-bold text-xs flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            AUDIT RATING: PASS
          </span>
        );
      case 'CONDITIONAL_PASS':
        return (
          <span className="px-3 py-1 rounded-full bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-200 border border-amber-300 dark:border-amber-800 font-bold text-xs flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            AUDIT RATING: CONDITIONAL PASS (GAPS FOUND)
          </span>
        );
      case 'HIGH_RISK_FAIL':
        return (
          <span className="px-3 py-1 rounded-full bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 border border-red-300 dark:border-red-800 font-bold text-xs flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-red-600" />
            AUDIT RATING: NON-COMPLIANT / HIGH RISK
          </span>
        );
    }
  };

  const handleCopyReport = () => {
    const markdown = `# Formal Regulatory & Security Compliance Audit Report
**Target Apex:** ${report.scannedDomain}
**Evaluation Timestamp:** ${new Date(report.evaluatedAt).toUTCString()}
**Overall Compliance Score:** ${report.overallComplianceScore}/100 (${report.overallAuditRating})

## Framework Alignment Summary:
- **NIST SP 800-53 Rev. 5:** ${report.summaries.NIST_SP_800_53.compliancePercentage}% (${report.summaries.NIST_SP_800_53.compliantCount}/${report.summaries.NIST_SP_800_53.totalControls} Controls Met)
- **NIST CSF v2.0:** ${report.summaries.NIST_CSF.compliancePercentage}% (${report.summaries.NIST_CSF.compliantCount}/${report.summaries.NIST_CSF.totalControls} Controls Met)
- **CIS Controls v8:** ${report.summaries.CIS_V8.compliancePercentage}% (${report.summaries.CIS_V8.compliantCount}/${report.summaries.CIS_V8.totalControls} Controls Met)
- **ISO/IEC 27001:2022:** ${report.summaries.ISO_27001.compliancePercentage}% (${report.summaries.ISO_27001.compliantCount}/${report.summaries.ISO_27001.totalControls} Controls Met)
- **PCI-DSS v4.0:** ${report.summaries.PCI_DSS.compliancePercentage}% (${report.summaries.PCI_DSS.compliantCount}/${report.summaries.PCI_DSS.totalControls} Controls Met)

## Itemized Control Findings:
${report.checks.map(c => `### [${c.status}] ${c.frameworkLabel} - ${c.controlId}: ${c.controlName}
- **Observed Evidence:** ${c.observedEvidence}
- **Auditor Assessment:** ${c.technicalFinding}
${c.evaluatedResources && c.evaluatedResources.length > 0 ? `- **Evaluated Perimeter Resources (${c.evaluatedResources.length}):**\n${c.evaluatedResources.map(r => `  * [${r.status}] ${r.resourceIdentifier}\n    - Evaluated Configuration: ${r.evaluatedConfiguration}\n    - Criteria: ${r.complianceCriteria}\n    - Source: ${r.reperformanceSource || 'N/A'}${r.reperformanceCommand ? `\n    - Reperformance CLI: ${r.reperformanceCommand}` : ''}`).join('\n')}` : ''}
${c.impactedResources && c.impactedResources.length > 0 ? `- **Impacted Non-Compliant Violations (${c.impactedResources.length}):**\n${c.impactedResources.map(r => `  * [${r.type.toUpperCase()}] ${r.resourceIdentifier} - Issue: ${r.observedIssue} (Current: ${r.currentValue || 'N/A'} | Required: ${r.expectedValue || 'N/A'})`).join('\n')}` : ''}
${c.reperformanceSource ? `- **Reperformance Source:** ${c.reperformanceSource}` : ''}
${c.reperformanceCommand ? `- **Reperformance Command:** \`${c.reperformanceCommand}\`` : ''}
- **Mandated Remediation:** ${c.mandatedFix}
- **Citation:** ${c.frameworkCitation}
`).join('\n')}

---
Generated by SurfaceTrace Enterprise Compliance Engine
`;
    navigator.clipboard.writeText(markdown);
    setCopiedBriefing(true);
    setTimeout(() => setCopiedBriefing(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Executive Summary Score Card */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xs transition-colors space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800 flex items-center gap-1.5">
                <Scale className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                REGULATORY & BENCHMARK COMPLIANCE AUDIT
              </span>
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                Target: <strong className="text-slate-800 dark:text-slate-200">{scan.domain}</strong>
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight">
              External Boundary Compliance & Control Mapping
            </h2>

            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 max-w-3xl leading-relaxed">
              Maps verified perimeter telemetry directly to formal requirements in <strong>NIST SP 800-53 Rev. 5</strong>, <strong>NIST CSF v2.0</strong>, <strong>CIS Controls v8</strong>, <strong>ISO/IEC 27001:2022</strong>, and <strong>PCI-DSS v4.0</strong>. External attack surface posture directly dictates regulatory audit readiness.
            </p>

            {/* Action Buttons */}
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                onClick={handleCopyReport}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
              >
                {copiedBriefing ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedBriefing ? 'Copied Full Audit Report' : 'Copy Compliance Report (Markdown)'}</span>
              </button>

              <button
                onClick={() => window.print()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-slate-500" />
                <span>Export Formal PDF / Print</span>
              </button>
            </div>
          </div>

          {/* Compliance Meter */}
          <div className="flex items-center gap-4 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 p-5 rounded-2xl shrink-0">
            <div className="space-y-1 text-center sm:text-left">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Overall Compliance Index
              </div>
              <div className="text-3xl font-extrabold font-mono text-slate-900 dark:text-white">
                {report.overallComplianceScore}<span className="text-slate-400 text-lg font-normal">/100</span>
              </div>
              <div className="pt-1">
                {getRatingBadge(report.overallAuditRating)}
              </div>
            </div>
          </div>
        </div>

        {/* 5 Framework Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-4 border-t border-slate-100 dark:border-slate-800/80">
          {(Object.keys(report.summaries) as ComplianceFramework[]).map((fwKey) => {
            const sum = report.summaries[fwKey];
            const isSelected = activeFrameworkFilter === fwKey;
            return (
              <div
                key={fwKey}
                onClick={() => setActiveFrameworkFilter(isSelected ? 'ALL' : fwKey)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-blue-50/80 dark:bg-blue-950/40 border-blue-400 dark:border-blue-600 shadow-xs'
                    : 'bg-slate-50/70 dark:bg-slate-950/40 hover:bg-white dark:hover:bg-slate-850 border-slate-200/80 dark:border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-semibold text-slate-600 dark:text-slate-300 mb-1">
                  <span className="truncate">{sum.frameworkName}</span>
                  <span className="font-mono font-bold text-slate-900 dark:text-white">{sum.compliancePercentage}%</span>
                </div>
                
                {/* Visual Progress Bar */}
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                  <div 
                    className={`h-full rounded-full ${
                      sum.compliancePercentage >= 85 ? 'bg-emerald-500' :
                      sum.compliancePercentage >= 60 ? 'bg-amber-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${sum.compliancePercentage}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400">
                  <span>{sum.compliantCount}/{sum.totalControls} Controls Met</span>
                  {sum.nonCompliantCount > 0 && (
                    <span className="text-red-600 dark:text-red-400 font-bold">{sum.nonCompliantCount} Gaps</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Interactive Controls Breakdown & Filtering */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <span>Evaluated Regulatory Controls ({filteredChecks.length})</span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Select any control to inspect technical telemetry evidence, auditor analysis, and mandatory remediation
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Status Filter */}
            <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg">
              <button
                onClick={() => setActiveStatusFilter('ALL')}
                className={`px-2 py-0.5 rounded cursor-pointer ${activeStatusFilter === 'ALL' ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white font-bold shadow-xs' : 'text-slate-600 dark:text-slate-400'}`}
              >
                All Status
              </button>
              <button
                onClick={() => setActiveStatusFilter('COMPLIANT')}
                className={`px-2 py-0.5 rounded cursor-pointer ${activeStatusFilter === 'COMPLIANT' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-600 dark:text-slate-400'}`}
              >
                Pass
              </button>
              <button
                onClick={() => setActiveStatusFilter('NON_COMPLIANT')}
                className={`px-2 py-0.5 rounded cursor-pointer ${activeStatusFilter === 'NON_COMPLIANT' ? 'bg-red-600 text-white font-bold' : 'text-slate-600 dark:text-slate-400'}`}
              >
                Fail
              </button>
              <button
                onClick={() => setActiveStatusFilter('PARTIALLY_COMPLIANT')}
                className={`px-2 py-0.5 rounded cursor-pointer ${activeStatusFilter === 'PARTIALLY_COMPLIANT' ? 'bg-amber-600 text-white font-bold' : 'text-slate-600 dark:text-slate-400'}`}
              >
                Partial
              </button>
            </div>

            {activeFrameworkFilter !== 'ALL' && (
              <button
                onClick={() => setActiveFrameworkFilter('ALL')}
                className="px-2.5 py-1 rounded bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-medium text-xs border border-blue-200 dark:border-blue-800 cursor-pointer"
              >
                Clear FW: {activeFrameworkFilter} ✕
              </button>
            )}
          </div>
        </div>

        {/* Controls List */}
        <div className="space-y-3">
          {filteredChecks.map((check) => {
            const isExpanded = expandedControlId === check.id;
            const statusConfig = STATUS_CONFIG[check.status];

            return (
              <div
                key={check.id}
                className={`rounded-xl border transition-all ${
                  check.status === 'COMPLIANT'
                    ? 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-200 dark:border-slate-800'
                    : check.status === 'NON_COMPLIANT'
                    ? 'bg-red-50/40 dark:bg-red-950/20 border-red-200 dark:border-red-900/60'
                    : 'bg-amber-50/40 dark:bg-amber-950/20 border-amber-200 dark:border-amber-900/60'
                }`}
              >
                <div
                  onClick={() => setExpandedControlId(isExpanded ? null : check.id)}
                  className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-100/50 dark:hover:bg-slate-800/40 rounded-xl"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <div className="mt-0.5 sm:mt-0">
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      )}
                    </div>

                    <div>
                      <div className="flex flex-wrap items-center gap-2 mb-0.5">
                        <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                          {check.controlId}
                        </span>
                        <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                          {check.frameworkLabel}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                          {check.controlFamily}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                        {check.controlName}
                      </h4>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-start sm:self-auto pl-7 sm:pl-0">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border flex items-center gap-1 ${statusConfig.badgeClass}`}>
                      {statusConfig.icon}
                      <span>{statusConfig.label}</span>
                    </span>
                  </div>
                </div>

                {/* Expanded Details Panel */}
                {isExpanded && (
                  <div className="p-4 pt-0 border-t border-slate-200/60 dark:border-slate-800/60 mt-2 space-y-3 text-xs animate-in fade-in-50">
                    <div className="text-slate-600 dark:text-slate-300 leading-relaxed font-sans pt-3">
                      {check.description}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                      {/* Observed Evidence */}
                      <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 block font-sans">
                          Tested Artifact & Observed Telemetry
                        </span>
                        <p className="font-mono text-[11px] text-slate-700 dark:text-slate-300">
                          {check.observedEvidence}
                        </p>
                        <div className="text-[10px] text-slate-400 pt-1">
                          Source: <span className="font-mono">{check.testedArtifact}</span>
                        </div>
                      </div>

                      {/* Auditor Assessment */}
                      <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-blue-600 dark:text-blue-400 block font-sans">
                          Auditor Finding & Guidance
                        </span>
                        <p className="text-slate-700 dark:text-slate-300 font-sans text-[11px] leading-relaxed">
                          {check.technicalFinding}
                        </p>
                        <p className="text-[10px] text-slate-500 dark:text-slate-400 italic">
                          Audit Tip: {check.auditorGuidance}
                        </p>
                      </div>
                    </div>

                    {/* Evaluated Resources & Configuration Audit */}
                    {check.evaluatedResources && check.evaluatedResources.length > 0 && (
                      <div className="p-3.5 rounded-xl bg-slate-100/70 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/80 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5 font-sans">
                            <Layers className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                            <span>Evaluated Perimeter Resources & Active Configurations ({check.evaluatedResources.length})</span>
                          </span>
                          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                            Audit Trail & Evidence
                          </span>
                        </div>

                        <div className="space-y-2.5">
                          {check.evaluatedResources.map((resource, idx) => {
                            let icon = <Server className="w-3.5 h-3.5 text-slate-500 shrink-0" />;
                            if (resource.type === 'subdomain') icon = <Globe className="w-3.5 h-3.5 text-blue-500 shrink-0" />;
                            else if (resource.type === 'certificate') icon = <Lock className="w-3.5 h-3.5 text-purple-500 shrink-0" />;
                            else if (resource.type === 'http_header') icon = <Server className="w-3.5 h-3.5 text-indigo-500 shrink-0" />;
                            else if (resource.type === 'cookie') icon = <Cookie className="w-3.5 h-3.5 text-amber-500 shrink-0" />;
                            else if (resource.type === 'dns_record') icon = <Key className="w-3.5 h-3.5 text-emerald-500 shrink-0" />;
                            else if (resource.type === 'endpoint') icon = <Globe className="w-3.5 h-3.5 text-cyan-500 shrink-0" />;

                            const isResourceCompliant = resource.status === 'COMPLIANT';
                            const cmdKey = `${check.id}-res-${idx}`;

                            return (
                              <div
                                key={idx}
                                className={`p-3 rounded-lg border text-xs space-y-2 transition-all ${
                                  isResourceCompliant
                                    ? 'bg-white/95 dark:bg-slate-900/90 border-emerald-200/80 dark:border-emerald-900/50 shadow-2xs'
                                    : 'bg-white/95 dark:bg-slate-900/90 border-red-200/80 dark:border-red-900/50 shadow-2xs'
                                }`}
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <div className="flex items-center gap-2 min-w-0">
                                    {icon}
                                    <span className="font-mono font-bold text-slate-900 dark:text-white break-all text-[11px]">
                                      {resource.resourceIdentifier}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-1.5 shrink-0">
                                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                                      {resource.type.replace('_', ' ')}
                                    </span>
                                    <span
                                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                                        isResourceCompliant
                                          ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                                          : 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-300 dark:border-red-800'
                                      }`}
                                    >
                                      {isResourceCompliant ? (
                                        <CheckCircle className="w-3 h-3 text-emerald-600" />
                                      ) : (
                                        <XCircle className="w-3 h-3 text-red-600" />
                                      )}
                                      <span>{resource.status}</span>
                                    </span>
                                  </div>
                                </div>

                                {/* Evaluated Configuration */}
                                <div className={`p-2 rounded font-mono text-[11px] leading-relaxed break-all ${
                                  isResourceCompliant
                                    ? 'bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-950 dark:text-emerald-200 border border-emerald-200/60 dark:border-emerald-900/40'
                                    : 'bg-red-50/70 dark:bg-red-950/30 text-red-950 dark:text-red-200 border border-red-200/60 dark:border-red-900/40'
                                }`}>
                                  <div className="text-[10px] font-sans font-bold uppercase tracking-wider mb-1 flex items-center gap-1 text-slate-500 dark:text-slate-400">
                                    {isResourceCompliant ? 'Identified Compliant Configuration' : 'Identified Non-Compliant Configuration'}
                                  </div>
                                  <div>{resource.evaluatedConfiguration}</div>
                                </div>

                                {/* Criteria and Reperformance Source */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-slate-600 dark:text-slate-300 pt-0.5">
                                  <div className="space-y-0.5">
                                    <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                                      Compliance Benchmark Standard
                                    </span>
                                    <span className="font-sans text-[11px] text-slate-700 dark:text-slate-300 leading-tight block">
                                      {resource.complianceCriteria}
                                    </span>
                                  </div>

                                  {resource.reperformanceSource && (
                                    <div className="space-y-0.5">
                                      <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                                        Reperformance Evidence Source
                                      </span>
                                      <span className="font-mono text-[10px] text-slate-700 dark:text-slate-300 leading-tight block break-all">
                                        {resource.reperformanceSource}
                                      </span>
                                    </div>
                                  )}
                                </div>

                                {/* Reperformance Command Snippet */}
                                {resource.reperformanceCommand && (
                                  <div className="p-2 rounded bg-slate-900 text-slate-200 font-mono text-[10px] flex items-center justify-between gap-2 overflow-x-auto border border-slate-800">
                                    <div className="flex items-center gap-1.5 min-w-0">
                                      <Terminal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                      <span className="text-slate-400 select-none">$</span>
                                      <span className="truncate">{resource.reperformanceCommand}</span>
                                    </div>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleCopyCommand(resource.reperformanceCommand!, cmdKey);
                                      }}
                                      className="shrink-0 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1 border border-slate-700 cursor-pointer"
                                      title="Copy reperformance command"
                                    >
                                      {copiedCommand === cmdKey ? (
                                        <Check className="w-3 h-3 text-emerald-400" />
                                      ) : (
                                        <Copy className="w-3 h-3 text-slate-400" />
                                      )}
                                      <span>{copiedCommand === cmdKey ? 'Copied' : 'Reperform'}</span>
                                    </button>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Impacted Non-Compliant Violations (if present) */}
                    {check.status !== 'COMPLIANT' && check.impactedResources && check.impactedResources.length > 0 && (
                      <div className="p-3.5 rounded-xl bg-red-50/60 dark:bg-red-950/20 border border-red-200/80 dark:border-red-900/60 space-y-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-red-800 dark:text-red-300 flex items-center gap-1.5 font-sans">
                            <AlertOctagon className="w-3.5 h-3.5 text-red-600 dark:text-red-400 shrink-0" />
                            <span>Actionable Remediation Discrepancies ({check.impactedResources.length})</span>
                          </span>
                          <span className="text-[10px] text-red-600 dark:text-red-400 font-mono">
                            Non-Compliance Gaps
                          </span>
                        </div>

                        <div className="space-y-2">
                          {check.impactedResources.map((resource, idx) => {
                            let icon = <AlertOctagon className="w-3.5 h-3.5 text-red-500 shrink-0" />;
                            if (resource.type === 'subdomain') icon = <Globe className="w-3.5 h-3.5 text-red-500 shrink-0" />;
                            else if (resource.type === 'certificate') icon = <Lock className="w-3.5 h-3.5 text-red-500 shrink-0" />;
                            else if (resource.type === 'http_header') icon = <Server className="w-3.5 h-3.5 text-red-500 shrink-0" />;
                            else if (resource.type === 'cookie') icon = <Cookie className="w-3.5 h-3.5 text-red-500 shrink-0" />;
                            else if (resource.type === 'dns_record') icon = <Key className="w-3.5 h-3.5 text-red-500 shrink-0" />;

                            return (
                              <div
                                key={idx}
                                className="p-2.5 rounded-lg bg-white/90 dark:bg-slate-900/90 border border-red-200/60 dark:border-red-900/40 text-xs space-y-1.5 shadow-2xs"
                              >
                                <div className="flex flex-wrap items-center justify-between gap-1.5">
                                  <div className="flex items-center gap-2 min-w-0">
                                    {icon}
                                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200 break-all text-[11px]">
                                      {resource.resourceIdentifier}
                                    </span>
                                  </div>
                                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 shrink-0">
                                    {resource.type.replace('_', ' ')}
                                  </span>
                                </div>

                                <p className="text-slate-600 dark:text-slate-300 text-[11px] leading-relaxed">
                                  <span className="font-semibold text-slate-700 dark:text-slate-200">Violation:</span> {resource.observedIssue}
                                </p>

                                {(resource.currentValue || resource.expectedValue) && (
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-0.5 font-mono text-[10px]">
                                    {resource.currentValue && (
                                      <div className="bg-slate-100 dark:bg-slate-800/80 px-2 py-1 rounded text-slate-700 dark:text-slate-300 break-all">
                                        <span className="text-red-600 dark:text-red-400 font-bold">Observed:</span> {resource.currentValue}
                                      </div>
                                    )}
                                    {resource.expectedValue && (
                                      <div className="bg-emerald-50 dark:bg-emerald-950/40 px-2 py-1 rounded text-emerald-800 dark:text-emerald-300 break-all">
                                        <span className="font-bold text-emerald-700 dark:text-emerald-400">Required:</span> {resource.expectedValue}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Check-Level Reperformance Command */}
                    {check.reperformanceCommand && (
                      <div className="p-3 rounded-lg bg-slate-900 text-slate-100 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-emerald-400 flex items-center gap-1.5 font-sans">
                            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Auditor Reperformance Command</span>
                          </span>
                          {check.reperformanceSource && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              Source: {check.reperformanceSource}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <code className="font-mono text-[11px] text-emerald-300 break-all select-all">
                            {check.reperformanceCommand}
                          </code>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopyCommand(check.reperformanceCommand!, `check-${check.id}`);
                            }}
                            className="shrink-0 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1 border border-slate-700 cursor-pointer"
                          >
                            {copiedCommand === `check-${check.id}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5 text-slate-400" />
                            )}
                            <span>{copiedCommand === `check-${check.id}` ? 'Copied' : 'Copy CLI'}</span>
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Mandated Fix */}
                    {check.status !== 'COMPLIANT' && (
                      <div className="p-3 rounded-lg bg-amber-50/70 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/80 space-y-1">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-amber-800 dark:text-amber-300 block font-sans">
                          Mandated Remediation for Audit Sign-Off
                        </span>
                        <code className="block font-mono text-[11px] text-amber-900 dark:text-amber-200 break-all">
                          {check.mandatedFix}
                        </code>
                      </div>
                    )}

                    <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                      <span>Statutory Citation: <strong className="text-slate-600 dark:text-slate-300">{check.frameworkCitation}</strong></span>
                      <span className="font-mono">Weight: {check.scoreImpact} pts</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
