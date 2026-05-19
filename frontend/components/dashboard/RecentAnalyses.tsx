import Link from 'next/link'

const analyses = [
  { id: 'anl_001', name: 'invoice.exe', risk: 'HIGH' },
  { id: 'anl_002', name: 'payload.dll', risk: 'CRITICAL' },
  { id: 'anl_003', name: 'dropper.bin', risk: 'MEDIUM' },
]

export default function RecentAnalyses() {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Recent Analyses</h3>
      <div className="mt-3 space-y-2">
        {analyses.map((item) => (
          <Link key={item.id} href={`/analysis/${item.id}`} className="flex items-center justify-between rounded-md border border-(--surface-border) px-3 py-2 hover:bg-slate-50">
            <span className="font-mono text-sm">{item.name}</span>
            <span className="text-xs text-muted">{item.risk}</span>
          </Link>
        ))}
      </div>
    </section>
  )
}