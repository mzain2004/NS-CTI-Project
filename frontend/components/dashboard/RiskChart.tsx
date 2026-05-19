export default function RiskChart() {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Risk Distribution</h3>
      <p className="mb-3 text-sm text-muted">Live risk stratification from Groq + static heuristics.</p>
      <div className="space-y-2 text-sm">
        <div className="flex items-center justify-between"><span>Critical</span><span className="font-semibold text-red-700">12%</span></div>
        <div className="flex items-center justify-between"><span>High</span><span className="font-semibold text-orange-700">23%</span></div>
        <div className="flex items-center justify-between"><span>Medium</span><span className="font-semibold text-amber-700">39%</span></div>
        <div className="flex items-center justify-between"><span>Low</span><span className="font-semibold text-emerald-700">26%</span></div>
      </div>
    </section>
  )
}