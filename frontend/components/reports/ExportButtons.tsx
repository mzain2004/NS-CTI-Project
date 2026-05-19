'use client'

import { useState } from 'react'

import Button from '@/components/ui/button'
import { generateReport } from '@/lib/api'

interface ExportButtonsProps {
  analysisId: string
}

export default function ExportButtons({ analysisId }: ExportButtonsProps) {
  const [message, setMessage] = useState('')

  async function handleGenerate() {
    const response = await generateReport(analysisId, 'SOC-A')
    setMessage(`Generated ${response.exports.length} export(s)`) 
  }

  return (
    <div className="panel p-4">
      <div className="flex items-center gap-2">
        <Button onClick={handleGenerate}>Generate Exports</Button>
      </div>
      <p className="mt-2 text-sm text-muted">{message}</p>
    </div>
  )
}
