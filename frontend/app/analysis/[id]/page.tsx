import IoCTable from '@/components/analysis/IoCTable'
import MitrePanel from '@/components/analysis/MitrePanel'
import StaticAnalysisPanel from '@/components/analysis/StaticAnalysisPanel'
import YaraPanel from '@/components/analysis/YaraPanel'
import { getAnalysisById } from '@/lib/api'
import type { AnalysisResult } from '@shared/types'

interface AnalysisPageProps {
  params: Promise<{ id: string }>
}

export default async function AnalysisDetailPage({ params }: AnalysisPageProps) {
  const { id } = await params
  let data: AnalysisResult | null = null
  try {
    data = await getAnalysisById(id)
  } catch {
    // API unavailable — render graceful fallback
  }

  if (!data) {
    return (
      <section className="stack-lg">
        <h1 className="title-xl">Analysis {id}</h1>
        <p className="text-muted">Unable to load analysis data. The backend may be unavailable.</p>
      </section>
    )
  }

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Analysis {id}</h1>
        <p className="text-muted">Detailed static signals, ATT&amp;CK mapping, and IoC extraction.</p>
      </header>
      <StaticAnalysisPanel data={data.static_analysis} />
      <div className="grid-2">
        <MitrePanel groq={data.groq_analysis} />
        <IoCTable iocs={data.groq_analysis?.iocs ?? null} />
      </div>
      <YaraPanel hits={data.static_analysis?.yara_hits ?? []} />
    </section>
  )
}