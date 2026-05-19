import RuleManager from '@/components/pfsense/RuleManager'

export default function PfSensePage() {
  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">pfSense Rules</h1>
        <p className="text-muted">Trigger defensive blocks from analysis and threat intel events.</p>
      </header>
      <RuleManager />
    </section>
  )
}