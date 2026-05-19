import type { CowrieSession } from '@shared/types'

interface SessionFeedProps {
  sessions: CowrieSession[]
}

export default function SessionFeed({ sessions }: SessionFeedProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Session Feed</h3>
      <div className="mt-3 space-y-2">
        {sessions.map((session) => (
          <article key={session.session_id} className="rounded-md border border-(--surface-border) p-2 text-sm">
            <p className="font-mono">{session.src_ip}:{session.src_port}</p>
            <p className="text-muted">{session.protocol.toUpperCase()} -> {session.username ?? 'n/a'}</p>
          </article>
        ))}
      </div>
    </section>
  )
}