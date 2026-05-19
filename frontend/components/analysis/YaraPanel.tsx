import type { YaraHit } from '@shared/types'

interface YaraPanelProps {
  hits: YaraHit[]
}

export default function YaraPanel({ hits }: YaraPanelProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">YARA Matches</h3>
      <div className="mt-3 space-y-2 text-sm">
        {hits.length === 0 ? <p>No matches.</p> : null}
        {hits.map((hit) => (
          <div key={hit.rule_name} className="rounded-md border border-(--surface-border) p-2">
            <p className="font-medium">{hit.rule_name}</p>
            <p className="text-muted">{hit.description}</p>
          </div>
        ))}
      </div>
    </section>
  )
}