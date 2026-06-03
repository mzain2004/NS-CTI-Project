import AlertTable from '@/components/wazuh/AlertTable'
import { getWazuhAlerts } from '@/lib/api'

export default async function WazuhPage() {
  let alerts: Awaited<ReturnType<typeof getWazuhAlerts>> = []
  try {
    const payload = await getWazuhAlerts()
    alerts = Array.isArray(payload) ? payload : []
  } catch {
    // API unavailable at build/request time — render empty state
  }

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Wazuh Alerts</h1>
        <p className="text-muted">Incoming SIEM detections with rule metadata and MITRE context.</p>
      </header>
      {alerts.length === 0 ? (
        <div className="alert alert-warning">
          Wazuh Not Configured — deploy Wazuh manager to enable
        </div>
      ) : (
        <AlertTable alerts={alerts} />
      )}
    </section>
  )
}