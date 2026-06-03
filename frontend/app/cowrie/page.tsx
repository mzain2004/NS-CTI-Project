import SamplePicker from '@/components/cowrie/SamplePicker'
import SessionFeed from '@/components/cowrie/SessionFeed'
import { getCowrieLogs, getCowrieSamples } from '@/lib/api'
import type { CowrieSession, CowrieSample } from '@shared/types'

export default async function CowriePage() {
  let sessions: CowrieSession[] = []
  let samples: CowrieSample[] = []
  try {
    const [sessionsPayload, samplesPayload] = await Promise.all([getCowrieLogs(), getCowrieSamples()])
    sessions = Array.isArray(sessionsPayload) ? sessionsPayload : []
    samples = Array.isArray(samplesPayload) ? samplesPayload : []
  } catch {
    // API unavailable at build/request time — render empty state
  }

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Cowrie Feed</h1>
        <p className="text-muted">Monitor honeypot sessions and pick captured payloads for analysis.</p>
      </header>
      <div className="alert alert-warning">
        Cowrie Honeypot Not Configured — deploy cowrie to enable
      </div>
      <div className="grid-2">
        <SessionFeed sessions={sessions} />
        <SamplePicker samples={samples} />
      </div>
    </section>
  )
}