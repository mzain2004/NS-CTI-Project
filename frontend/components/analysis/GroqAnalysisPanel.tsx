import type { GroqAnalysis } from '@shared/types'

interface GroqAnalysisPanelProps {
  data: GroqAnalysis | null
}

export default function GroqAnalysisPanel({ data }: GroqAnalysisPanelProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Groq Analysis</h3>
      <p className="text-sm text-muted">Structured malware family and behavior interpretation.</p>
      <p className="mt-3 text-sm">Family: {data?.malware_family ?? 'Unknown'}</p>
    </section>
  )
}