"use client"
import { useEffect, useState } from 'react';
import ExportButtons from '@/components/reports/ExportButtons';
import ReportCard from '@/components/reports/ReportCard';
import type { ReportMetadata } from '@shared/types';
import { API_URL } from '@/lib/api'

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportMetadata[]>([]);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const response = await fetch(`${API_URL}/api/report/list`);
        const data = await response.json();
        setReports(data);
      } catch (error) {
        console.error('Failed to fetch reports:', error);
      }
    };

    fetchReports();
    const interval = setInterval(fetchReports, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const handleGenerateReport = async (analysisId: string) => {
    try {
      const response = await fetch(`${API_URL}/api/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis_id: analysisId }),
      });

      if (response.ok) {
        alert('Report generation started successfully!');
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

