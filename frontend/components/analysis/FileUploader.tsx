'use client'

import { useState } from 'react'

import Button from '@/components/ui/button'
import { analyzeFile } from '@/lib/api'
import type { AnalysisResult } from '@shared/types'

interface FileUploaderProps {
  onComplete: (result: AnalysisResult) => void
}

export default function FileUploader({ onComplete }: FileUploaderProps) {
  const [busy, setBusy] = useState(false)

  async function handleChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setBusy(true)
    try {
      const result = await analyzeFile(file)
      onComplete(result)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Upload Sample</h3>
      <p className="text-sm text-muted">Supported: PE, script, and binary payload files.</p>
      <div className="mt-3 flex items-center gap-3">
        <input type="file" onChange={handleChange} className="text-sm" />
        <Button disabled={busy}>{busy ? 'Analyzing...' : 'Ready'}</Button>
      </div>
    </section>
  )
}