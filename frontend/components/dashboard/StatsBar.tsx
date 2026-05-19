const stats = [
  { label: 'Analyses Today', value: '37' },
  { label: 'Critical Detections', value: '5' },
  { label: 'Cowrie Sessions', value: '89' },
  { label: 'Wazuh Alerts', value: '142' },
]

export default function StatsBar() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {stats.map((item) => (
        <article key={item.label} className="panel p-3">
          <p className="text-xs uppercase tracking-wide text-muted">{item.label}</p>
          <p className="mt-1 text-xl font-semibold">{item.value}</p>
        </article>
      ))}
    </div>
  )
}