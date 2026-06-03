"use client"
import { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, Tooltip } from 'recharts';
import { API_URL } from '@/lib/api'

const COLORS = ['#dc2626', '#f59e0b', '#22c55e', '#6366f1'];

interface RecentAnalysis {
  id: string;
  filename: string;
  risk_level: string;
  sha256: string;
  time_ago: string;
}

interface RiskItem {
  name: string;
  value: number;
}

type DashboardAnalysis = {
  created_at?: string;
  file_name?: string;
  hashes?: { sha256?: string };
  static_analysis?: { sha256?: string } | null;
  groq_analysis?: {
    risk_level?: string;
    iocs?: {
      ips?: string[];
      domains?: string[];
      urls?: string[];
      hashes?: string[];
      registry_keys?: string[];
      file_paths?: string[];
      mutexes?: string[];
    } | null;
  } | null;
  risk_level?: string;
};

type DashboardStats = {
  filesAnalyzed: number;
  threatsDetected: number;
  iocsExtracted: number;
  wazuhAlerts: number;
};

function normalizeRiskLevel(value?: string | null) {
  const risk = (value ?? 'LOW').toUpperCase();
  return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(risk) ? risk : 'LOW';
}

function computeTimeAgo(createdAt?: string) {
  if (!createdAt) return 'Unknown';
  const created = new Date(createdAt);
  if (Number.isNaN(created.getTime())) return 'Unknown';
  const diffMs = Date.now() - created.getTime();
  const diffHours = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60)));
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

function computeDashboardStats(analyses: DashboardAnalysis[]): DashboardStats {
  const threatCount = analyses.filter((analysis) => normalizeRiskLevel(analysis.groq_analysis?.risk_level ?? analysis.risk_level) !== 'LOW').length;
  const iocsExtracted = analyses.reduce((total, analysis) => {
    const iocs = analysis.groq_analysis?.iocs;
    if (!iocs) return total;
    return total + [
      iocs.ips,
      iocs.domains,
      iocs.urls,
      iocs.hashes,
      iocs.registry_keys,
      iocs.file_paths,
      iocs.mutexes,
    ].reduce((sum, items) => sum + (Array.isArray(items) ? items.length : 0), 0);
  }, 0);

  return {
    filesAnalyzed: analyses.length,
    threatsDetected: threatCount,
    iocsExtracted,
    wazuhAlerts: 0,
  };
}

function buildRiskDistribution(analyses: DashboardAnalysis[]): RiskItem[] {
  const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

  analyses.forEach((analysis) => {
    const risk = normalizeRiskLevel(analysis.groq_analysis?.risk_level ?? analysis.risk_level);
    counts[risk as keyof typeof counts] += 1;
  });

  return Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value }));
}

function buildRecentAnalyses(analyses: DashboardAnalysis[]): RecentAnalysis[] {
  return analyses.slice(0, 5).map((analysis, index) => ({
    id: analysis.hashes?.sha256 ?? analysis.static_analysis?.sha256 ?? analysis.file_name ?? `analysis-${index}`,
    filename: analysis.file_name ?? 'Unknown file',
    risk_level: normalizeRiskLevel(analysis.groq_analysis?.risk_level ?? analysis.risk_level),
    sha256: analysis.hashes?.sha256 ?? analysis.static_analysis?.sha256 ?? '',
    time_ago: computeTimeAgo(analysis.created_at),
  }));
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    filesAnalyzed: 0,
    threatsDetected: 0,
    iocsExtracted: 0,
    wazuhAlerts: 0,
  });
  const [riskDistribution, setRiskDistribution] = useState<RiskItem[]>([]);
  const [recentAnalyses, setRecentAnalyses] = useState<RecentAnalysis[]>([]);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [analysesResponse, wazuhResponse] = await Promise.all([
          fetch(`${API_URL}/api/analyze/list`),
          fetch(`${API_URL}/api/wazuh/stats`),
        ]);

        if (!analysesResponse.ok) {
          throw new Error(`Failed to fetch analyses: ${analysesResponse.status}`);
        }

        const analysesData = (await analysesResponse.json()) as DashboardAnalysis[];
        const wazuhData = wazuhResponse.ok ? await wazuhResponse.json() : { total_alerts: 0 };

        setStats({
          ...computeDashboardStats(Array.isArray(analysesData) ? analysesData : []),
          wazuhAlerts: Number(wazuhData?.total_alerts ?? 0),
        });
        setRiskDistribution(buildRiskDistribution(Array.isArray(analysesData) ? analysesData : []));
        setRecentAnalyses(buildRecentAnalyses(Array.isArray(analysesData) ? analysesData : []));
      } catch {
        // API unavailable — degrade with explicit empty dashboard state
        setStats({
          filesAnalyzed: 0,
          threatsDetected: 0,
          iocsExtracted: 0,
          wazuhAlerts: 0,
        });
        setRiskDistribution([]);
        setRecentAnalyses([]);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-[#f9fafb]">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4 mt-6">
        <div className="bg-[#1f2937] p-4 rounded">
          <p className="text-sm text-[#9ca3af]">Files Analyzed</p>
          <p className="text-2xl font-bold text-[#f9fafb]">{stats.filesAnalyzed}</p>
        </div>
        <div className="bg-[#1f2937] p-4 rounded">
          <p className="text-sm text-[#9ca3af]">Threats Detected</p>
          <p className="text-2xl font-bold text-[#f9fafb]">{stats.threatsDetected}</p>
        </div>
        <div className="bg-[#1f2937] p-4 rounded">
          <p className="text-sm text-[#9ca3af]">IoCs Extracted</p>
          <p className="text-2xl font-bold text-[#f9fafb]">{stats.iocsExtracted}</p>
        </div>
        <div className="bg-[#1f2937] p-4 rounded">
          <p className="text-sm text-[#9ca3af]">Wazuh Alerts</p>
          <p className="text-2xl font-bold text-[#f9fafb]">{stats.wazuhAlerts}</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mt-6">
        <div className="col-span-2 bg-[#1f2937] p-4 rounded">
          <h2 className="text-lg font-bold text-[#f9fafb]">Recent Analyses</h2>
          <table className="w-full mt-4 text-[#f9fafb]">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Risk Level</th>
                <th>SHA256</th>
                <th>Time Ago</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {recentAnalyses.map((analysis) => (
                <tr key={analysis.id}>
                  <td>{analysis.filename}</td>
                  <td>{analysis.risk_level}</td>
                  <td>{analysis.sha256.slice(0, 8)}</td>
                  <td>{analysis.time_ago}</td>
                  <td>
                    <button className="text-[#6366f1]">View</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="bg-[#1f2937] p-4 rounded">
          <h2 className="text-lg font-bold text-[#f9fafb]">Risk Distribution</h2>
          <PieChart width={300} height={300}>
              {(() => {
                const safeRisk = Array.isArray(riskDistribution) ? riskDistribution : [];
                return (
                  <Pie
                    data={safeRisk}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    fill="#8884d8"
                  >
                    {safeRisk.map((entry, index) => (
                      <Cell key={`cell-${entry.name}-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                );
              })()}
            <Tooltip />
          </PieChart>
        </div>
      </div>
    </div>
  );
}
