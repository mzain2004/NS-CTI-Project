export default function TopBar() {
  return (
    <header className="m-4 mb-0 rounded-2xl border border-(--surface-border) bg-white px-4 py-3">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted">Operational status</span>
        <span className="rounded-full bg-emerald-100 px-3 py-1 text-xs font-medium text-emerald-700">All systems nominal</span>
      </div>
    </header>
  )
}