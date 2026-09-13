import React, { useState } from 'react';
import { OSINT_TOOLS, MITRE_TACTIC_LIST } from '../data/osintTools';
import { OsintTool } from '../types';
import { 
  Search, ExternalLink, Filter, Layers, ShieldCheck, ShieldAlert,
  Terminal, Sparkles, Tag, ChevronDown, ChevronUp, Globe, CheckCircle2,
  Zap, Workflow, LayoutGrid, SlidersHorizontal, ArrowRight, Info, AlertTriangle,
  Cpu, Server, Key, Mail, Shield, Check, Eye
} from 'lucide-react';

interface OsintDirectoryTabProps {
  currentDomain: string;
}

type ViewMode = 'matrix' | 'killchain' | 'cards';

interface MitreTechniqueSummary {
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  description: string;
  tools: OsintTool[];
  hasSurfaceTraceIntegration: boolean;
}

export const OsintDirectoryTab: React.FC<OsintDirectoryTabProps> = ({ currentDomain }) => {
  const [viewMode, setViewMode] = useState<ViewMode>('matrix');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedTarget, setSelectedTarget] = useState<string>('ALL');
  const [selectedPricing, setSelectedPricing] = useState<string>('ALL');
  const [integrationFilter, setIntegrationFilter] = useState<'ALL' | 'INTEGRATED' | 'EXTERNAL'>('ALL');
  const [expandedToolId, setExpandedToolId] = useState<string | null>(null);
  const [activeTechniqueModal, setActiveTechniqueModal] = useState<MitreTechniqueSummary | null>(null);

  // Extract unique filter sets
  const categories = ['ALL', ...Array.from(new Set(OSINT_TOOLS.map(t => t.category)))];
  const targets = ['ALL', ...Array.from(new Set(OSINT_TOOLS.map(t => t.vulnerabilityTarget)))];

  // Group tools by MITRE techniques
  const techniqueMap = new Map<string, MitreTechniqueSummary>();

  OSINT_TOOLS.forEach(tool => {
    const techId = tool.mitreMapping.techniqueId;
    if (!techniqueMap.has(techId)) {
      techniqueMap.set(techId, {
        techniqueId: techId,
        techniqueName: tool.mitreMapping.techniqueName,
        tacticId: tool.mitreMapping.tacticId,
        tacticName: tool.mitreMapping.tacticName,
        description: tool.description,
        tools: [],
        hasSurfaceTraceIntegration: false,
      });
    }
    const tech = techniqueMap.get(techId)!;
    tech.tools.push(tool);
    if (tool.leveragedBySurfaceTrace) {
      tech.hasSurfaceTraceIntegration = true;
    }
  });

  const allTechniques = Array.from(techniqueMap.values());

  // Filter tools for directory cards view
  const filteredTools = OSINT_TOOLS.filter((tool) => {
    const matchesCategory = selectedCategory === 'ALL' || tool.category === selectedCategory;
    const matchesTarget = selectedTarget === 'ALL' || tool.vulnerabilityTarget === selectedTarget;
    const matchesPricing = selectedPricing === 'ALL' || tool.pricing.includes(selectedPricing);
    const matchesIntegration = 
      integrationFilter === 'ALL' || 
      (integrationFilter === 'INTEGRATED' && tool.leveragedBySurfaceTrace) ||
      (integrationFilter === 'EXTERNAL' && !tool.leveragedBySurfaceTrace);
    const matchesSearch = !searchQuery || 
      tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.enterpriseUseCases.some(u => u.toLowerCase().includes(searchQuery.toLowerCase())) ||
      tool.mitreMapping.techniqueId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.mitreMapping.techniqueName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesCategory && matchesTarget && matchesPricing && matchesIntegration && matchesSearch;
  });

  const toggleExpand = (id: string) => {
    setExpandedToolId(prev => prev === id ? null : id);
  };

  // Tactics for MITRE matrix view
  const matrixTactics = [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      count: '12 Techniques',
      summary: 'Adversary gathers target infrastructure intelligence without direct engagement.',
      borderColor: 'border-cyan-500/60 dark:border-cyan-400/50',
      headerBg: 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-900 dark:text-cyan-200',
      accent: 'cyan',
    },
    {
      id: 'TA0042',
      name: 'Resource Development',
      count: '9 Techniques',
      summary: 'Adversary establishes external staging assets, DNS takeovers, and infrastructure.',
      borderColor: 'border-amber-500/60 dark:border-amber-400/50',
      headerBg: 'bg-amber-50 dark:bg-amber-950/60 text-amber-900 dark:text-amber-200',
      accent: 'amber',
    },
    {
      id: 'TA0001',
      name: 'Initial Access',
      count: '11 Techniques',
      summary: 'Adversary pivots through weaponized web portals, spoofed emails, or unpatched CVEs.',
      borderColor: 'border-rose-500/60 dark:border-rose-400/50',
      headerBg: 'bg-rose-50 dark:bg-rose-950/60 text-rose-900 dark:text-rose-200',
      accent: 'rose',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header & Navigation Bar */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                  Curated Open Source Intelligence (OSINT) Directory
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  External reconnaissance platforms mapped directly against the MITRE ATT&CK® Enterprise Matrix
                </p>
              </div>
            </div>
          </div>

          {/* View Mode Switcher */}
          <div className="flex items-center p-1 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 shrink-0 text-xs font-medium">
            <button
              onClick={() => setViewMode('matrix')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                viewMode === 'matrix'
                  ? 'bg-blue-600 text-white font-semibold shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>ATT&CK Matrix</span>
            </button>
            <button
              onClick={() => setViewMode('killchain')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                viewMode === 'killchain'
                  ? 'bg-blue-600 text-white font-semibold shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <Workflow className="w-3.5 h-3.5" />
              <span>Recon Kill Chain</span>
            </button>
            <button
              onClick={() => setViewMode('cards')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                viewMode === 'cards'
                  ? 'bg-blue-600 text-white font-semibold shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>Directory Cards</span>
            </button>
          </div>
        </div>

        {/* Status Bar & Global Filters */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-slate-500 dark:text-slate-400 font-mono text-[11px] uppercase tracking-wider font-semibold">
              Filter by Integration:
            </span>
            <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-800 p-0.5 bg-slate-50 dark:bg-slate-950">
              <button
                onClick={() => setIntegrationFilter('ALL')}
                className={`px-2.5 py-1 rounded-md text-xs cursor-pointer transition-colors ${
                  integrationFilter === 'ALL'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white font-semibold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                }`}
              >
                All Tools ({OSINT_TOOLS.length})
              </button>
              <button
                onClick={() => setIntegrationFilter('INTEGRATED')}
                className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-xs cursor-pointer transition-colors ${
                  integrationFilter === 'INTEGRATED'
                    ? 'bg-emerald-600 text-white font-semibold shadow-xs'
                    : 'text-emerald-700 dark:text-emerald-400 hover:text-emerald-800'
                }`}
              >
                <Zap className="w-3 h-3" />
                <span>Natively in SurfaceTrace (4)</span>
              </button>
              <button
                onClick={() => setIntegrationFilter('EXTERNAL')}
                className={`px-2.5 py-1 rounded-md text-xs cursor-pointer transition-colors ${
                  integrationFilter === 'EXTERNAL'
                    ? 'bg-slate-700 text-white font-semibold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                }`}
              >
                External Reference (16)
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400 text-xs font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              SurfaceTrace Live Probing
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
              External Threat Telemetry
            </span>
          </div>
        </div>
      </div>

      {/* ========================================================= */}
      {/* VIEW 1: MITRE ATT&CK ENTERPRISE MATRIX NAVIGATOR DIAGRAM */}
      {/* ========================================================= */}
      {viewMode === 'matrix' && (
        <div className="space-y-4">
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-xs space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 font-mono uppercase tracking-wider text-[11px]">
                <Layers className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                MITRE ATT&CK® Enterprise Matrix Mapping (EASM Domain)
              </span>
              <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                Click any technique cell below to inspect mapped OSINT tools & workflows
              </span>
            </div>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
              Modeled after the MITRE ATT&CK Navigator, this interactive matrix maps open-source intelligence tools to their formal adversary techniques.
              Cards labeled with <span className="text-emerald-600 dark:text-emerald-400 font-semibold font-mono">⚡ Built-in</span> represent capabilities executed directly by SurfaceTrace's automated scanning engine.
            </p>
          </div>

          {/* Matrix Columns Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {matrixTactics.map((tactic) => {
              const techniquesInTactic = allTechniques.filter(t => t.tacticId === tactic.id);

              return (
                <div key={tactic.id} className="space-y-3 flex flex-col">
                  {/* Tactic Column Header (ATT&CK Matrix Style) */}
                  <div className={`p-3.5 rounded-xl border ${tactic.borderColor} ${tactic.headerBg} shadow-xs`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono font-bold text-xs tracking-wider uppercase">
                        {tactic.id}
                      </span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-white/70 dark:bg-slate-900/70 border border-current font-bold">
                        {techniquesInTactic.length} Techniques
                      </span>
                    </div>
                    <h3 className="font-bold text-sm tracking-tight">
                      {tactic.name}
                    </h3>
                    <p className="text-[11px] opacity-80 mt-1 line-clamp-2 leading-relaxed">
                      {tactic.summary}
                    </p>
                  </div>

                  {/* Technique Cells Stack */}
                  <div className="space-y-2.5 flex-1">
                    {techniquesInTactic.map((tech) => {
                      const displayedTools = tech.tools.filter(t => {
                        if (integrationFilter === 'INTEGRATED') return t.leveragedBySurfaceTrace;
                        if (integrationFilter === 'EXTERNAL') return !t.leveragedBySurfaceTrace;
                        return true;
                      });

                      if (displayedTools.length === 0 && integrationFilter !== 'ALL') return null;

                      const isSelected = activeTechniqueModal?.techniqueId === tech.techniqueId;

                      return (
                        <div
                          key={tech.techniqueId}
                          onClick={() => setActiveTechniqueModal(tech)}
                          className={`p-3.5 rounded-xl border transition-all cursor-pointer group ${
                            isSelected
                              ? 'bg-blue-50/80 dark:bg-blue-950/50 border-blue-500 shadow-sm ring-2 ring-blue-500/20'
                              : tech.hasSurfaceTraceIntegration
                              ? 'bg-white dark:bg-slate-900 border-emerald-200 dark:border-emerald-900/60 hover:border-emerald-400 dark:hover:border-emerald-700 shadow-xs'
                              : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700 shadow-xs'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <span className="font-mono font-bold text-xs text-slate-500 dark:text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                              {tech.techniqueId}
                            </span>
                            {tech.hasSurfaceTraceIntegration && (
                              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 flex items-center gap-1 shrink-0">
                                <Zap className="w-2.5 h-2.5" />
                                <span>Built-in</span>
                              </span>
                            )}
                          </div>

                          <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100 mt-1 line-clamp-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors leading-snug">
                            {tech.techniqueName}
                          </h4>

                          {/* Mapped OSINT Tool Badges */}
                          <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap gap-1">
                            {tech.tools.map((tool) => (
                              <span
                                key={tool.id}
                                className={`text-[10px] font-mono px-2 py-0.5 rounded border transition-colors ${
                                  tool.leveragedBySurfaceTrace
                                    ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800/80 font-semibold'
                                    : 'bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800'
                                }`}
                              >
                                {tool.name.split('(')[0].trim()}
                              </span>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Technique Detail Drawer / Inspector */}
          {activeTechniqueModal && (
            <div className="bg-white dark:bg-slate-900 border-2 border-blue-500 rounded-xl p-5 shadow-lg space-y-4 animate-in fade-in-50 mt-4">
              <div className="flex items-start justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-mono text-xs font-bold">
                      {activeTechniqueModal.techniqueId}
                    </span>
                    <span className="text-xs text-slate-500 font-mono uppercase tracking-wider">
                      {activeTechniqueModal.tacticName} ({activeTechniqueModal.tacticId})
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white mt-1">
                    {activeTechniqueModal.techniqueName}
                  </h3>
                </div>

                <button
                  onClick={() => setActiveTechniqueModal(null)}
                  className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 text-slate-600 dark:text-slate-300 text-xs font-mono cursor-pointer"
                >
                  Close ×
                </button>
              </div>

              {/* SurfaceTrace Engine Execution Banner */}
              <div className={`p-3.5 rounded-xl border flex items-start gap-3 ${
                activeTechniqueModal.hasSurfaceTraceIntegration
                  ? 'bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
                  : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300'
              }`}>
                {activeTechniqueModal.hasSurfaceTraceIntegration ? (
                  <Zap className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
                )}
                <div className="text-xs space-y-1">
                  <div className="font-bold flex items-center gap-2">
                    {activeTechniqueModal.hasSurfaceTraceIntegration 
                      ? 'Natively Audited by SurfaceTrace Scanning Engine'
                      : 'External Threat Intelligence Reference'}
                  </div>
                  <p className="leading-relaxed opacity-90">
                    {activeTechniqueModal.hasSurfaceTraceIntegration
                      ? 'When you run a scan on SurfaceTrace, our backend automatically interrogates the external attack surface for this technique without requiring manual analyst queries.'
                      : 'This technique involves active port scanning or authenticated vendor datasets. SurfaceTrace references these tools for manual auditor investigation.'}
                  </p>
                </div>
              </div>

              {/* Mapped OSINT Tools Details */}
              <div className="space-y-3">
                <span className="text-xs font-bold text-slate-700 dark:text-slate-300 font-mono uppercase tracking-wider block">
                  Mapped Tools for {activeTechniqueModal.techniqueId}:
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {activeTechniqueModal.tools.map((tool) => (
                    <div
                      key={tool.id}
                      className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <h4 className="font-bold text-slate-900 dark:text-white">
                          {tool.name}
                        </h4>
                        <a
                          href={tool.url}
                          target="_blank"
                          rel="noreferrer"
                          className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-blue-600 dark:text-blue-400 cursor-pointer"
                          title="Open tool URL"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>

                      <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                        {tool.description}
                      </p>

                      <div className="text-[11px] font-mono bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                        <span className="text-slate-400 font-bold block mb-0.5">Execution in SurfaceTrace:</span>
                        {tool.surfaceTraceIntegration}
                      </div>

                      <div className="pt-1">
                        <span className="text-[10px] font-mono font-bold text-blue-600 dark:text-blue-400 block mb-0.5">
                          Sample Recon Workflow:
                        </span>
                        <code className="text-[11px] font-mono text-slate-800 dark:text-slate-200 bg-slate-100 dark:bg-slate-950 px-2 py-1 rounded block break-all">
                          {tool.sampleWorkflow.replace('targetcompany.com', currentDomain || 'example.com')}
                        </code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* VIEW 2: ADVERSARY RECON-TO-BREACH KILL CHAIN PIPELINE   */}
      {/* ======================================================== */}
      {viewMode === 'killchain' && (
        <div className="space-y-6">
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-xs space-y-1">
            <span className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 font-mono uppercase tracking-wider text-[11px]">
              <Workflow className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              Adversary External Reconnaissance & Exploitation Flow
            </span>
            <p className="text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
              Adversaries do not deploy exploits randomly. They follow a deterministic progression from zero-footprint passive discovery to perimeter exploitation.
              This diagram illustrates how open-source intelligence tools feed into each stage of the kill chain.
            </p>
          </div>

          {/* Sequential 5-Stage Kill Chain Diagram */}
          <div className="relative space-y-4">
            {/* Stage 1 */}
            <div className="bg-white dark:bg-slate-900 border border-cyan-200 dark:border-cyan-900/60 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-lg bg-cyan-100 dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 font-mono font-bold text-xs flex items-center justify-center">
                    01
                  </span>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      Passive Surface Discovery (Zero Target Footprint)
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-cyan-50 dark:bg-cyan-950 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800 font-normal">
                        MITRE T1596 (Search Open Technical Databases)
                      </span>
                    </h3>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Adversary never sends a single packet to target servers. Queries third-party aggregators only.
                    </span>
                  </div>
                </div>

                <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-semibold flex items-center gap-1 w-fit">
                  <Zap className="w-3 h-3" /> SurfaceTrace Engine
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    crt.sh (Certificate Logs)
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Harvests all historical & active subdomains issued by public CAs. Uncovers staging and shadow IT environments.
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    DNS-over-HTTPS (DoH)
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Queries Cloudflare & Google public resolvers to map MX records, TXT verification tags, and CNAME chains.
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    SecurityTrails & DNSDumpster
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Examines 10-year historical IP assignments to uncover unprotected origin IP addresses bypassing CDN/WAF.
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Threat Dataset
                  </span>
                </div>
              </div>
            </div>

            {/* Down Arrow */}
            <div className="flex justify-center -my-2 text-slate-400 dark:text-slate-600">
              <ArrowRight className="w-5 h-5 rotate-90" />
            </div>

            {/* Stage 2 */}
            <div className="bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-900/60 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 font-mono font-bold text-xs flex items-center justify-center">
                    02
                  </span>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      Network Footprint & Perimeter Fingerprinting
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-normal">
                        MITRE T1590 (Network Info) & T1595 (Active Scanning)
                      </span>
                    </h3>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Maps Autonomous System Numbers (ASNs), BGP routing prefixes, hosting providers, and exposed TCP services.
                    </span>
                  </div>
                </div>

                <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800 font-semibold w-fit">
                  Network Intelligence
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    IP-API & BGPView
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Resolves ASN organization, country, and flags CDN edge proxies (Cloudflare, AWS CloudFront, Akamai).
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    Shodan & Censys
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Scans global IPv4 space for exposed management interfaces (RDP 3389, SSH 22, Elasticsearch 9200, Redis 6379).
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Port Scanner
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    GreyNoise
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Filters out benign scanner noise from adversary targeted recon hitting enterprise IP blocks.
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Threat Feed
                  </span>
                </div>
              </div>
            </div>

            {/* Down Arrow */}
            <div className="flex justify-center -my-2 text-slate-400 dark:text-slate-600">
              <ArrowRight className="w-5 h-5 rotate-90" />
            </div>

            {/* Stage 3 */}
            <div className="bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-900/60 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-lg bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 font-mono font-bold text-xs flex items-center justify-center">
                    03
                  </span>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      Vulnerability & Misconfiguration Harvesting
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-normal">
                        MITRE T1592 (Host Configurations) & T1584.004 (Server Hijacking)
                      </span>
                    </h3>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Identifies missing defensive headers, dangling DNS pointers, leaked API keys, and unauthenticated cloud storage.
                    </span>
                  </div>
                </div>

                <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 font-semibold flex items-center gap-1 w-fit">
                  <Zap className="w-3 h-3" /> SurfaceTrace Engine
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    HTTP Security Header Inspector
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Verifies HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and HttpOnly/SameSite cookie flags.
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    Can I Take Over XYZ (CNAME Takeovers)
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Matches CNAME answers against 16+ cloud signatures (AWS S3, GitHub Pages, Heroku, Azure) to detect orphan DNS records.
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    GitGuardian & GrayhatWarfare
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Uncovers leaked enterprise developer tokens in public repos and unauthenticated AWS S3 buckets.
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Cloud Repos
                  </span>
                </div>
              </div>
            </div>

            {/* Down Arrow */}
            <div className="flex justify-center -my-2 text-slate-400 dark:text-slate-600">
              <ArrowRight className="w-5 h-5 rotate-90" />
            </div>

            {/* Stage 4 */}
            <div className="bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900/60 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-lg bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 font-mono font-bold text-xs flex items-center justify-center">
                    04
                  </span>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      Initial Access & Exploitation (Breach Initiation)
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 font-normal">
                        MITRE T1190 (Exploit Public-Facing App) & T1566 (Phishing)
                      </span>
                    </h3>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Adversary executes remote code execution, claims dangling domains for phishing, or launches credential stuffing.
                    </span>
                  </div>
                </div>

                <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800 font-semibold w-fit">
                  High Severity Risk
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-blue-600 dark:text-blue-400 block text-[11px]">
                    SPF / DMARC Inspection
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Absence of `p=reject` allows adversaries to spoof company executives in CEO fraud / business email compromise (BEC).
                  </p>
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold block pt-1">
                    ✓ Native in SurfaceTrace
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    CISA KEV Catalog
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Directly cross-references identified web server versions against CVEs with known actively weaponized exploits.
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Exploit Feed
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-mono font-bold text-slate-700 dark:text-slate-300 block text-[11px]">
                    Have I Been Pwned (HIBP)
                  </span>
                  <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                    Compromised corporate credentials leaked in historical breaches are weaponized against enterprise SSO/VPN portals.
                  </p>
                  <span className="text-[10px] font-mono text-slate-500 font-bold block pt-1">
                    External Breach Feed
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================= */}
      {/* VIEW 3: CURATED TOOL DIRECTORY CARDS                      */}
      {/* ========================================================= */}
      {viewMode === 'cards' && (
        <div className="space-y-4">
          {/* Search & Multi-tier Filters */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-xs space-y-3">
            {/* Main Search */}
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search OSINT tools by name, use case, target asset, or MITRE technique..."
                className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all font-sans"
              />
            </div>

            {/* Filter Dropdowns */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                aria-label="Filter by Category"
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              >
                <option value="ALL">All Categories</option>
                {categories.filter(c => c !== 'ALL').map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>

              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                aria-label="Filter by Vulnerability Target"
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              >
                <option value="ALL">All Target Assets</option>
                {targets.filter(t => t !== 'ALL').map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>

              <select
                value={selectedPricing}
                onChange={(e) => setSelectedPricing(e.target.value)}
                aria-label="Filter by Access Model"
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              >
                <option value="ALL">All Pricing Models</option>
                <option value="100% Free">100% Free / Public</option>
                <option value="Free Tier">Free Tier / Freemium</option>
              </select>

              {(searchQuery || selectedCategory !== 'ALL' || selectedTarget !== 'ALL' || selectedPricing !== 'ALL' || integrationFilter !== 'ALL') && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setSelectedCategory('ALL');
                    setSelectedTarget('ALL');
                    setSelectedPricing('ALL');
                    setIntegrationFilter('ALL');
                  }}
                  className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 text-xs transition-colors cursor-pointer"
                >
                  Reset Filters
                </button>
              )}

              <span className="text-[11px] font-mono text-slate-500 ml-auto">
                Showing {filteredTools.length} of {OSINT_TOOLS.length} tools
              </span>
            </div>
          </div>

          {/* Tools Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredTools.map((tool) => {
              const isExpanded = expandedToolId === tool.id;

              return (
                <div
                  key={tool.id}
                  className={`bg-white dark:bg-slate-900 border rounded-xl p-5 shadow-xs flex flex-col justify-between transition-all space-y-4 ${
                    tool.leveragedBySurfaceTrace
                      ? 'border-emerald-200 dark:border-emerald-900/60 hover:border-emerald-400'
                      : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  {/* Top Row: Title, Badges & External Link */}
                  <div className="space-y-2">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-blue-600 dark:text-blue-400">
                            {tool.category}
                          </span>
                          {tool.leveragedBySurfaceTrace && (
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800 flex items-center gap-1">
                              <Zap className="w-2.5 h-2.5" /> Built-in
                            </span>
                          )}
                        </div>
                        <h3 className="text-base font-bold text-slate-900 dark:text-white">
                          {tool.name}
                        </h3>
                      </div>

                      <a
                        href={tool.url}
                        target="_blank"
                        rel="noreferrer"
                        className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-blue-400 text-blue-600 dark:text-blue-400 transition-colors shrink-0 shadow-xs cursor-pointer"
                        title={`Open ${tool.name} in new tab`}
                      >
                        <ExternalLink className="w-4 h-4" />
                      </a>
                    </div>

                    {/* Metadata Badges */}
                    <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                      <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800">
                        {tool.pricing}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/70 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800/60 font-semibold font-sans">
                        Target: {tool.vulnerabilityTarget}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/70 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 flex items-center gap-1 font-semibold">
                        <Layers className="w-2.5 h-2.5 text-blue-600 dark:text-blue-400" />
                        {tool.mitreMapping.techniqueId}
                      </span>
                    </div>

                    {/* Description */}
                    <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed font-sans pt-1">
                      {tool.description}
                    </p>
                  </div>

                  {/* SurfaceTrace Integration Note */}
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-[11px] font-mono">
                    <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-0.5 block font-sans">
                      {tool.leveragedBySurfaceTrace ? '⚡ SurfaceTrace Integration' : '🔍 External Analyst Reference'}
                    </span>
                    <span className="text-slate-700 dark:text-slate-300 leading-normal">
                      {tool.surfaceTraceIntegration}
                    </span>
                  </div>

                  {/* Enterprise Use Cases Breakdown */}
                  <div className="space-y-2 border-t border-slate-100 dark:border-slate-800/80 pt-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
                        Vulnerability Detection:
                      </span>
                      <button
                        onClick={() => toggleExpand(tool.id)}
                        className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 flex items-center gap-0.5 font-sans font-medium cursor-pointer"
                      >
                        <span>{isExpanded ? 'Less' : 'View all'}</span>
                        {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                    </div>

                    <ul className="space-y-1 text-xs text-slate-700 dark:text-slate-300 font-sans">
                      {(isExpanded ? tool.enterpriseUseCases : tool.enterpriseUseCases.slice(0, 2)).map((useCase, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-[11px] leading-relaxed">
                          <span className="text-blue-600 dark:text-blue-400 mt-0.5">•</span>
                          <span>{useCase}</span>
                        </li>
                      ))}
                    </ul>

                    {/* Investigative Workflow Snippet */}
                    <div className="p-2 rounded-lg bg-slate-100/70 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-[11px] font-mono mt-2">
                      <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 flex items-center gap-1 font-sans">
                        <Terminal className="w-3 h-3 text-blue-600 dark:text-blue-400" /> Sample Recon Workflow
                      </div>
                      <div className="text-slate-700 dark:text-slate-300 break-all">
                        {tool.sampleWorkflow.replace('targetcompany.com', currentDomain || 'target.com')}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
