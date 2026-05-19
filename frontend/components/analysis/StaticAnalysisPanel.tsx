import type { StaticAnalysis } from '@shared/types'

interface StaticAnalysisPanelProps {
  data: StaticAnalysis | null
}

export default function StaticAnalysisPanel({ data }: StaticAnalysisPanelProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Static Analysis</h3>
      <p className="text-sm text-muted">PE sections, imports, entropy, and local heuristics.</p>
      <p className="mt-3 font-mono text-sm">SHA256: {data?.sha256 ?? 'N/A'}</p>
    </section>
  )
}