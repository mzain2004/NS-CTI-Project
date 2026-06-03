"use client"
import { useEffect, useState } from 'react';
import ReportCard from '@/components/reports/ReportCard';
import type { ReportListItem } from '@/lib/api';
import { generateReport, listReports } from '@/lib/api'

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportListItem[]>([]);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const data = await listReports();
        setReports(Array.isArray(data) ? data : []);
      } catch (error) {
        console.error('Failed to fetch reports:', error);
        setReports([]);
      }
    };

    fetchReports();
    const interval = setInterval(fetchReports, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const handleGenerateReport = async (analysisId: string) => {
    try {
      const result = await generateReport(analysisId, 'SOC-A');
      if (result.report_id) {
        alert('Report generation started successfully!');
        const refreshed = await listReports();
        setReports(Array.isArray(refreshed) ? refreshed : []);
      } else {
        alert('Failed to start report generation.');
      }
    } catch (error) {
      console.error('Error generating report:', error);
      alert('An error occurred while generating the report.');
    }
  };

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Reports</h1>
        <p className="text-muted">Generate and export PDF, JSON, and IOC text reports from completed analyses.</p>
      </header>
      <button
        className="btn btn-primary"
        onClick={() => handleGenerateReport('example_analysis_id')}
      >
        Generate Report
      </button>
      <div className="stack-md">
        {reports.map((report) => (
          <ReportCard key={report.report_id} report={report} />
        ))}
      </div>
    </section>
  );
}

