import React, { useState, useEffect } from 'react';
import { 
  Database, Download, Terminal, RefreshCw, Trash2, Search, 
  CheckCircle2, AlertTriangle, FileText, ArrowRight, Play,
  HardDrive, Activity, ShieldAlert, Globe, Layers, Clock, Cpu
} from 'lucide-react';
import { sqliteManager, SqlQueryResult } from '../lib/sqliteDatabase';
import { EasmScanResult } from '../types';

interface SqlDatabaseTabProps {
  currentScan: EasmScanResult | null;
  onLoadHistoricalScan?: (domain: string) => void;
}

export const SqlDatabaseTab: React.FC<SqlDatabaseTabProps> = ({ 
  currentScan,
  onLoadHistoricalScan
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'logs' | 'scans' | 'console'>('logs');
  const [metrics, setMetrics] = useState({
    totalScans: 0,
    totalLogs: 0,
    totalFindings: 0,
    totalSubdomains: 0,
    dbSizeFormatted: '0 KB'
  });
  const [logsData, setLogsData] = useState<any[]>([]);
  const [scansData, setScansData] = useState<any[]>([]);
  const [searchLog, setSearchLog] = useState('');
  const [isExporting, setIsExporting] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // SQL Console State
  const [sqlQuery, setSqlQuery] = useState<string>(
    `SELECT id, source_service, status_code, latency_ms, target_endpoint\nFROM network_logs\nORDER BY timestamp DESC\nLIMIT 20;`
  );
  const [queryResult, setQueryResult] = useState<SqlQueryResult | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);

  // Load metrics and tables
  useEffect(() => {
    let isMounted = true;

    async function loadDbInfo() {
      try {
        const m = await sqliteManager.getMetrics();
        if (!isMounted) return;
        setMetrics(m);

        // Load network logs
        const logsRes = await sqliteManager.executeQuery(`
          SELECT id, scan_id, timestamp, source_service, protocol, status_code, latency_ms, target_endpoint, details
          FROM network_logs
          ORDER BY timestamp DESC
          LIMIT 100;
        `);

        // Load scans
        const scansRes = await sqliteManager.executeQuery(`
          SELECT id, domain, timestamp, health_score, subdomain_count, findings_count, apex_ip, asn_org, status
          FROM scans
          ORDER BY timestamp DESC;
        `);

        if (isMounted) {
          if (logsRes.values) {
            setLogsData(logsRes.values.map(row => {
              const obj: any = {};
              logsRes.columns.forEach((col, idx) => { obj[col] = row[idx]; });
              return obj;
            }));
          }

          if (scansRes.values) {
            setScansData(scansRes.values.map(row => {
              const obj: any = {};
              scansRes.columns.forEach((col, idx) => { obj[col] = row[idx]; });
              return obj;
            }));
          }
        }
      } catch (err) {
        console.error('Failed to load SQLite metrics:', err);
      }
    }

    loadDbInfo();
    return () => { isMounted = false; };
  }, [refreshTrigger, currentScan?.domain]);

  // Execute SQL Query
  const handleRunQuery = async () => {
    if (!sqlQuery.trim()) return;
    setIsExecuting(true);
    try {
      const res = await sqliteManager.executeQuery(sqlQuery.trim());
      setQueryResult(res);
    } catch (err: any) {
      setQueryResult({
        columns: [],
        values: [],
        executionTimeMs: 0,
        error: err.message || 'Execution error'
      });
    } finally {
      setIsExecuting(false);
    }
  };

  // Preset SQL Queries
  const PRESET_QUERIES = [
    {
      label: 'Recent Network Telemetry Logs',
      sql: `SELECT id, source_service, status_code, latency_ms, target_endpoint\nFROM network_logs\nORDER BY timestamp DESC\nLIMIT 25;`
    },
    {
      label: 'Critical & High Vulnerabilities',
      sql: `SELECT title, category, severity, mitre_technique, affected_asset\nFROM findings\nWHERE severity IN ('critical', 'high')\nORDER BY severity ASC;`
    },
    {
      label: 'Average Latency by Recon Service',
      sql: `SELECT source_service, COUNT(*) as queries_run, ROUND(AVG(latency_ms), 1) as avg_latency_ms\nFROM network_logs\nGROUP BY source_service\nORDER BY avg_latency_ms ASC;`
    },
    {
      label: 'Subdomains by Provider Takeover Risk',
      sql: `SELECT hostname, status, detected_provider, ip_address\nFROM subdomains\nWHERE status = 'dangling' OR detected_provider IS NOT NULL\nLIMIT 25;`
    },
    {
      label: 'Scans & Hygiene Summary',
      sql: `SELECT domain, health_score, findings_count, subdomain_count, datetime(timestamp/1000, 'unixepoch') as scanned_at\nFROM scans\nORDER BY timestamp DESC;`
    }
  ];

  // Export handlers
  const handleExportSqlite = async () => {
    setIsExporting(true);
    try {
      const blob = await sqliteManager.exportSqliteBinary();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `surfacetrace_easm_${Date.now()}.sqlite`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export SQLite binary:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportSqlDump = async () => {
    setIsExporting(true);
    try {
      const sql = await sqliteManager.exportSqlDump();
      const blob = new Blob([sql], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `surfacetrace_dump_${Date.now()}.sql`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export SQL dump:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportJson = async () => {
    setIsExporting(true);
    try {
      const json = await sqliteManager.exportJson();
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `surfacetrace_export_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export JSON:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportCsv = async () => {
    setIsExporting(true);
    try {
      const csv = await sqliteManager.exportNetworkLogsCsv();
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network_logs_${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export CSV:', err);
    } finally {
      setIsExporting(false);
    }
  };

  const handleResetDb = async () => {
    if (window.confirm('Are you sure you want to erase all local scans and network telemetry records? This cannot be undone.')) {
      await sqliteManager.resetDatabase();
      setRefreshTrigger(prev => prev + 1);
      setQueryResult(null);
    }
  };

  // Filtered network logs
  const filteredLogs = logsData.filter(log => {
    if (!searchLog) return true;
    const q = searchLog.toLowerCase();
    return (
      log.source_service?.toLowerCase().includes(q) ||
      log.target_endpoint?.toLowerCase().includes(q) ||
      log.details?.toLowerCase().includes(q) ||
      String(log.status_code).includes(q)
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-in fade-in-50">
      {/* Top Banner & Metrics */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-xs space-y-6 transition-colors">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-5">
          <div className="flex items-center space-x-3.5">
            <div className="w-11 h-11 rounded-xl bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                  Browser-Side SQLite Telemetry & Audit Vault
                </h2>
                <span className="px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 text-[10px] font-mono font-bold border border-blue-200 dark:border-blue-800">
                  WASM v3.45+ • IndexedDB Persisted
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Every external reconnaissance request, DNS query, and discovered asset is saved to an encrypted client-side relational database.
              </p>
            </div>
          </div>

          {/* Export & Vault Actions */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleExportSqlite}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
              title="Download binary .sqlite database file for SQLite3 / DBeaver"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export .sqlite</span>
            </button>

            <button
              onClick={handleExportSqlDump}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
              title="Download plain SQL DDL and INSERT script"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export .sql</span>
            </button>

            <button
              onClick={handleExportJson}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
              title="Export complete relational dump as JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>JSON</span>
            </button>

            <button
              onClick={handleExportCsv}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
              title="Export network logs to CSV"
            >
              <Download className="w-3.5 h-3.5" />
              <span>CSV Logs</span>
            </button>

            <button
              onClick={handleResetDb}
              className="p-1.5 rounded-lg bg-red-50 hover:bg-red-100 dark:bg-red-950/40 dark:hover:bg-red-900/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 transition-colors cursor-pointer"
              title="Reset Local Database"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
            <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Database Size</span>
            <div className="text-lg font-bold font-mono text-slate-900 dark:text-white mt-1">
              {metrics.dbSizeFormatted}
            </div>
            <span className="text-[10px] text-slate-400">IndexedDB synced</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
            <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Total Scans</span>
            <div className="text-lg font-bold font-mono text-blue-600 dark:text-blue-400 mt-1">
              {metrics.totalScans}
            </div>
            <span className="text-[10px] text-slate-400">scans table</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
            <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Network Logs</span>
            <div className="text-lg font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">
              {metrics.totalLogs}
            </div>
            <span className="text-[10px] text-slate-400">network_logs table</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
            <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Indexed Findings</span>
            <div className="text-lg font-bold font-mono text-amber-600 dark:text-amber-400 mt-1">
              {metrics.totalFindings}
            </div>
            <span className="text-[10px] text-slate-400">findings table</span>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
            <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">Total Subdomains</span>
            <div className="text-lg font-bold font-mono text-purple-600 dark:text-purple-400 mt-1">
              {metrics.totalSubdomains}
            </div>
            <span className="text-[10px] text-slate-400">subdomains table</span>
          </div>
        </div>
      </div>

      {/* Segmented Sub-Navigation */}
      <div className="flex items-center space-x-2 border-b border-slate-200 dark:border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('logs')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeSubTab === 'logs'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Network Telemetry Logs ({logsData.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('scans')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeSubTab === 'scans'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          <span>Historical Scans ({scansData.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('console')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeSubTab === 'console'
              ? 'bg-blue-600 text-white shadow-xs'
              : 'bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Interactive SQL Query Console</span>
        </button>
      </div>

      {/* SUB-VIEW 1: NETWORK TELEMETRY LOGS */}
      {activeSubTab === 'logs' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Live Captured Network Reconnaissance Logs
              </h3>
              <p className="text-xs text-slate-500">
                Passive external probes logged with latency, HTTP status code, and endpoint details
              </p>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Filter logs by endpoint/service..."
                value={searchLog}
                onChange={(e) => setSearchLog(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 text-xs text-slate-900 dark:text-slate-100 focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-950/60 text-slate-500 font-mono font-semibold border-b border-slate-200 dark:border-slate-800">
                  <th className="p-2.5">ID</th>
                  <th className="p-2.5">Source Service</th>
                  <th className="p-2.5">Protocol</th>
                  <th className="p-2.5">Status</th>
                  <th className="p-2.5">Latency</th>
                  <th className="p-2.5">Target Endpoint</th>
                  <th className="p-2.5">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-[11px]">
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                      <td className="p-2.5 text-slate-400">#{log.id}</td>
                      <td className="p-2.5 font-sans font-semibold text-slate-800 dark:text-slate-200">
                        {log.source_service}
                      </td>
                      <td className="p-2.5 text-slate-500">{log.protocol}</td>
                      <td className="p-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          log.status_code === 200 
                            ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60'
                            : 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60'
                        }`}>
                          HTTP {log.status_code}
                        </span>
                      </td>
                      <td className="p-2.5 text-blue-600 dark:text-blue-400 font-bold">
                        {log.latency_ms} ms
                      </td>
                      <td className="p-2.5 text-slate-600 dark:text-slate-300 max-w-xs truncate" title={log.target_endpoint}>
                        {log.target_endpoint}
                      </td>
                      <td className="p-2.5 text-slate-500 font-sans max-w-xs truncate" title={log.details}>
                        {log.details}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-400 font-sans">
                      No network logs found. Run a domain scan above to record network telemetry into SQLite.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUB-VIEW 2: HISTORICAL SCANS */}
      {activeSubTab === 'scans' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Archived Scan History in SQLite
              </h3>
              <p className="text-xs text-slate-500">
                Complete historical perimeter runs stored persistently in your browser
              </p>
            </div>
          </div>

          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-950/60 text-slate-500 font-mono font-semibold border-b border-slate-200 dark:border-slate-800">
                  <th className="p-2.5">Domain</th>
                  <th className="p-2.5">Timestamp</th>
                  <th className="p-2.5">Health Score</th>
                  <th className="p-2.5">Subdomains</th>
                  <th className="p-2.5">Findings</th>
                  <th className="p-2.5">Apex IP / ASN</th>
                  <th className="p-2.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-sans">
                {scansData.length > 0 ? (
                  scansData.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                      <td className="p-2.5 font-bold text-blue-600 dark:text-blue-400 font-mono">
                        {s.domain}
                      </td>
                      <td className="p-2.5 text-slate-500 font-mono text-[11px]">
                        {new Date(s.timestamp).toLocaleString()}
                      </td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                          s.health_score >= 80 
                            ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                            : s.health_score >= 60
                            ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                            : 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                        }`}>
                          {s.health_score} / 100
                        </span>
                      </td>
                      <td className="p-2.5 font-mono text-slate-700 dark:text-slate-300 font-bold">
                        {s.subdomain_count}
                      </td>
                      <td className="p-2.5 font-mono text-slate-700 dark:text-slate-300 font-bold">
                        {s.findings_count}
                      </td>
                      <td className="p-2.5 text-slate-500 font-mono text-[11px]">
                        {s.apex_ip} ({s.asn_org || 'N/A'})
                      </td>
                      <td className="p-2.5 text-right">
                        {onLoadHistoricalScan && (
                          <button
                            onClick={() => onLoadHistoricalScan(s.domain)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-mono text-[11px] font-medium transition-colors cursor-pointer"
                          >
                            <span>Load Scan</span>
                            <ArrowRight className="w-3 h-3 text-blue-600" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-400">
                      No archived scans found in SQLite.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUB-VIEW 3: INTERACTIVE SQL CONSOLE */}
      {activeSubTab === 'console' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <span>Interactive SQLite Query Console</span>
            </h3>
            <p className="text-xs text-slate-500">
              Directly query the browser-side SQLite engine using standard SQL syntax. Tables: <code className="font-mono text-blue-600 dark:text-blue-400 font-semibold">scans</code>, <code className="font-mono text-blue-600 dark:text-blue-400 font-semibold">network_logs</code>, <code className="font-mono text-blue-600 dark:text-blue-400 font-semibold">findings</code>, <code className="font-mono text-blue-600 dark:text-blue-400 font-semibold">subdomains</code>.
            </p>
          </div>

          {/* Presets */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400 mr-1">Query Presets:</span>
            {PRESET_QUERIES.map((preset) => (
              <button
                key={preset.label}
                onClick={() => setSqlQuery(preset.sql)}
                className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[11px] transition-colors cursor-pointer border border-slate-200 dark:border-slate-700"
              >
                {preset.label}
              </button>
            ))}
          </div>

          {/* SQL Editor */}
          <div className="space-y-2">
            <textarea
              rows={4}
              value={sqlQuery}
              onChange={(e) => setSqlQuery(e.target.value)}
              className="w-full p-3 rounded-lg bg-slate-950 text-slate-100 font-mono text-xs border border-slate-800 focus:outline-hidden focus:ring-1 focus:ring-blue-500 leading-relaxed"
              placeholder="SELECT * FROM network_logs LIMIT 10;"
            />

            <div className="flex items-center justify-between">
              <span className="text-[11px] text-slate-500 font-mono">
                Powered by sql.js (WebAssembly SQLite v3.45)
              </span>

              <button
                onClick={handleRunQuery}
                disabled={isExecuting}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>{isExecuting ? 'Executing...' : 'Run Query'}</span>
              </button>
            </div>
          </div>

          {/* Results Table */}
          {queryResult && (
            <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-600 dark:text-slate-400">
                  {queryResult.error ? (
                    <span className="text-red-500 font-bold flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" /> SQLite Error: {queryResult.error}
                    </span>
                  ) : (
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium">
                      Query OK: {queryResult.values.length} rows returned in {queryResult.executionTimeMs} ms
                    </span>
                  )}
                </span>
              </div>

              {!queryResult.error && queryResult.columns.length > 0 && (
                <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg max-h-96">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="sticky top-0 bg-slate-100 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800">
                      <tr className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                        {queryResult.columns.map((col) => (
                          <th key={col} className="p-2.5 font-bold">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono text-[11px]">
                      {queryResult.values.map((row, rIdx) => (
                        <tr key={rIdx} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                          {row.map((val, cIdx) => (
                            <td key={cIdx} className="p-2.5 text-slate-700 dark:text-slate-300 max-w-xs truncate" title={String(val ?? 'NULL')}>
                              {val === null || val === undefined ? (
                                <span className="text-slate-400 italic">NULL</span>
                              ) : (
                                String(val)
                              )}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
