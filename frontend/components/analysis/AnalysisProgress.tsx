import type { AnalysisResult } from '@shared/types'

interface AnalysisProgressProps {
  analysis: AnalysisResult | null
}

export default function AnalysisProgress({ analysis }: AnalysisProgressProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Analysis Progress</h3>
      <p className="text-sm text-muted">Track static and AI enrichment pipeline status.</p>
      <p className="mt-3 text-sm">Current: {analysis?.status ?? 'idle'}</p>
    </section>
  )
}