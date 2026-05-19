'use client'

import { useState } from 'react'

import AnalysisProgress from '@/components/analysis/AnalysisProgress'
import FileUploader from '@/components/analysis/FileUploader'
import GroqAnalysisPanel from '@/components/analysis/GroqAnalysisPanel'
import StaticAnalysisPanel from '@/components/analysis/StaticAnalysisPanel'
import VirusTotalPanel from '@/components/analysis/VirusTotalPanel'
import type { AnalysisResult } from '@shared/types'

export default function AnalyzePage() {
  const [result, setResult] = useState<AnalysisResult | null>(null)

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Analyze Malware</h1>
        <p className="text-muted">Upload a suspicious sample and run the full static + AI pipeline.</p>
      </header>
      <FileUploader onComplete={setResult} />
      <AnalysisProgress analysis={result} />
      <div className="grid-2">
        <StaticAnalysisPanel data={result?.static_analysis ?? null} />
        <GroqAnalysisPanel data={result?.groq_analysis ?? null} />
      </div>
      <VirusTotalPanel data={result?.virustotal ?? null} />
    </section>
  )
}