'use client'

import { useState } from 'react'

import Button from '@/components/ui/button'
import { blockPfSense } from '@/lib/api'

export default function RuleManager() {
  const [ip, setIp] = useState('')
  const [status, setStatus] = useState('')

  async function handleBlock() {
    const response = await blockPfSense({
      ip,
      reason: 'manual platform block',
      analysis_id: null,
      duration_hours: null,
    })
    setStatus(response.message)
  }

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Rule Manager</h3>
      <div className="mt-3 flex gap-2">
        <input value={ip} onChange={(event) => setIp(event.target.value)} placeholder="IP to block" className="rounded-lg border border-(--surface-border) px-3 py-2 text-sm" />
        <Button onClick={handleBlock}>Block IP</Button>
      </div>
      <p className="mt-2 text-sm text-muted">{status}</p>
    </section>
  )
}