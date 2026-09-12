import React, { useState } from 'react';
import { OSINT_TOOLS } from '../data/osintTools';
import { OsintTool } from '../types';
import { 
  Search, ExternalLink, Filter, Layers, ShieldCheck, 
  Terminal, Sparkles, Tag, ChevronDown, ChevronUp, Globe, CheckCircle2
} from 'lucide-react';

interface OsintDirectoryTabProps {
  currentDomain: string;
}

export const OsintDirectoryTab: React.FC<OsintDirectoryTabProps> = ({ currentDomain }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedTarget, setSelectedTarget] = useState<string>('ALL');
  const [selectedPricing, setSelectedPricing] = useState<string>('ALL');
  const [expandedToolId, setExpandedToolId] = useState<string | null>(null);

  // Extract unique filter sets
  const categories = ['ALL', ...Array.from(new Set(OSINT_TOOLS.map(t => t.category)))];
  const targets = ['ALL', ...Array.from(new Set(OSINT_TOOLS.map(t => t.vulnerabilityTarget)))];
  const pricings = ['ALL', '100% Free', 'Free Tier / Freemium'];

  // Filter tools
  const filteredTools = OSINT_TOOLS.filter((tool) => {
    const matchesCategory = selectedCategory === 'ALL' || tool.category === selectedCategory;
    const matchesTarget = selectedTarget === 'ALL' || tool.vulnerabilityTarget === selectedTarget;
    const matchesPricing = selectedPricing === 'ALL' || tool.pricing.includes(selectedPricing);
    const matchesSearch = !searchQuery || 
      tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.enterpriseUseCases.some(u => u.toLowerCase().includes(searchQuery.toLowerCase())) ||
      tool.mitreMapping.techniqueId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.mitreMapping.techniqueName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesCategory && matchesTarget && matchesPricing && matchesSearch;
  });

  const toggleExpand = (id: string) => {
    setExpandedToolId(prev => prev === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Header & Description */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-xs space-y-4 transition-colors">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Curated Open Source Intelligence (OSINT) Directory
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Verified OSINT platforms & databases for mapping corporate digital footprints, discovering shadow IT, and auditing external vulnerabilities
            </p>
          </div>

          <div className="text-xs font-mono text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/60 px-3 py-1.5 rounded-lg border border-blue-200 dark:border-blue-800 font-semibold">
            {filteredTools.length} of {OSINT_TOOLS.length} Verified Tools
          </div>
        </div>

        {/* Search & Multi-tier Filters */}
        <div className="space-y-3">
          {/* Main Search */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3.5 top-3 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search OSINT tools by name, use case, vulnerability target, or MITRE technique..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all font-sans"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Category Filter */}
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              aria-label="Filter by Category"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
            >
              <option value="ALL">All Intelligence Categories</option>
              {categories.filter(c => c !== 'ALL').map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>

            {/* Target Asset Filter */}
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              aria-label="Filter by Vulnerability Target"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
            >
              <option value="ALL">All Vulnerability Targets</option>
              {targets.filter(t => t !== 'ALL').map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>

            {/* Pricing Model */}
            <select
              value={selectedPricing}
              onChange={(e) => setSelectedPricing(e.target.value)}
              aria-label="Filter by Access Model"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
            >
              <option value="ALL">All Access Models</option>
              <option value="100% Free">100% Free / Public</option>
              <option value="Free Tier">Free Tier / Freemium</option>
            </select>

            {(searchQuery || selectedCategory !== 'ALL' || selectedTarget !== 'ALL' || selectedPricing !== 'ALL') && (
              <button
                onClick={() => {
                  setSearchQuery('');
                  setSelectedCategory('ALL');
                  setSelectedTarget('ALL');
                  setSelectedPricing('ALL');
                }}
                className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 text-xs transition-colors cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* OSINT Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredTools.map((tool) => {
          const isExpanded = expandedToolId === tool.id;

          return (
            <div
              key={tool.id}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 rounded-xl p-5 shadow-xs flex flex-col justify-between transition-all space-y-4"
            >
              {/* Top Row: Title, Badges & External Link */}
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-blue-600 dark:text-blue-400 block mb-0.5">
                      {tool.category}
                    </span>
                    <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                      {tool.name}
                    </h3>
                  </div>

                  <a
                    href={tool.url}
                    target="_blank"
                    rel="noreferrer"
                    className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-blue-400 dark:hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-950/40 text-blue-600 dark:text-blue-400 transition-colors shrink-0 shadow-xs cursor-pointer"
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

              {/* Enterprise Use Cases Breakdown */}
              <div className="space-y-2 border-t border-slate-100 dark:border-slate-800/80 pt-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
                    Vulnerability Detection Use Cases:
                  </span>
                  <button
                    onClick={() => toggleExpand(tool.id)}
                    className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 flex items-center gap-0.5 font-sans font-medium cursor-pointer"
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
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80 text-xs font-mono mt-2">
                  <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider mb-1 flex items-center gap-1 font-sans">
                    <Terminal className="w-3 h-3 text-blue-600 dark:text-blue-400" /> Sample Recon Workflow
                  </div>
                  <div className="text-slate-700 dark:text-slate-300 text-[11px] break-all">
                    {tool.sampleWorkflow.replace('targetcompany.com', currentDomain || 'target.com')}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
