import type { ReportMetadata } from '@shared/types'
import type { ReportListItem } from '@/lib/api'

interface ReportCardProps {
  report: ReportMetadata | ReportListItem
}

export default function ReportCard({ report }: ReportCardProps) {
  return (
    <article className="panel p-4">
      <h3 className="font-semibold">{report.file_name ?? 'Generated report'}</h3>
      <p className="text-sm text-muted">Report ID: {report.report_id}</p>
      <p className="font-mono text-xs">{report.sha256 ?? 'SHA256 unavailable'}</p>
    </article>
  )
}