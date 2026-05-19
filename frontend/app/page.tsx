import { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, Tooltip } from 'recharts';

const COLORS = ['#dc2626', '#f59e0b', '#22c55e', '#6366f1'];

export default function DashboardPage() {
  const [stats, setStats] = useState({
    filesAnalyzed: 0,
    threatsDetected: 0,
    iocsExtracted: 0,
    wazuhAlerts: 0,
  });
  const [riskDistribution, setRiskDistribution] = useState([]);
  const [recentAnalyses, setRecentAnalyses] = useState([]);

  useEffect(() => {
    const fetchStats = async () => {
      const statsResponse = await fetch('/api/dashboard/stats');
      const statsData = await statsResponse.json();
      setStats(statsData);

      const riskResponse = await fetch('/api/dashboard/risk-distribution');
      const riskData = await riskResponse.json();
      setRiskDistribution(riskData);

      const analysesResponse = await fetch('/api/analyze/list');
      const analysesData = await analysesResponse.json();
      setRecentAnalyses(analysesData);
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
            <Pie
              data={riskDistribution}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={100}
              fill="#8884d8"
            >
              {riskDistribution.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </div>
      </div>
    </div>
  );
}
