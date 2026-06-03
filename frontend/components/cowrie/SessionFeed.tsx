"use client"
import type { CowrieSession } from '@shared/types'

interface SessionFeedProps {
  sessions: CowrieSession[]
}

export default function SessionFeed({ sessions }: SessionFeedProps) {
  const safeSessions = Array.isArray(sessions) ? sessions : []

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Session Feed</h3>
      <div className="mt-3 space-y-2">
        {safeSessions.map((session, index) => (
          <article key={session.session_id ?? `session-${index}`} className="rounded-md border border-(--surface-border) p-2 text-sm">
            <p className="font-mono">{session.src_ip ?? 'unknown'}:{session.src_port ?? 'n/a'}</p>
            <p className="text-muted">{(session.protocol ?? 'unknown').toUpperCase()} {'->'} {session.username ?? 'n/a'}</p>
          </article>
        ))}
      </div>
    </section>
  )
}