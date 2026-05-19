import type { VirusTotalResult } from '@shared/types'

interface VirusTotalPanelProps {
  data: VirusTotalResult | null
}

export default function VirusTotalPanel({ data }: VirusTotalPanelProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">VirusTotal</h3>
      <p className="text-sm text-muted">External reputation and multi-engine verdict summary.</p>
      <p className="mt-3 text-sm">Detection ratio: {data?.detection_ratio ?? 'N/A'}</p>
    </section>
  )
}