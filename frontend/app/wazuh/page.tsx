import AlertTable from '@/components/wazuh/AlertTable'
import { getWazuhAlerts } from '@/lib/api'

export default async function WazuhPage() {
  const alerts = await getWazuhAlerts()

  return (
    <section className="stack-lg">
      <header className="stack-sm">
        <h1 className="title-xl">Wazuh Alerts</h1>
        <p className="text-muted">Incoming SIEM detections with rule metadata and MITRE context.</p>
      </header>
      <div className="alert alert-warning">
        Wazuh Not Configured — deploy Wazuh manager to enable
      </div>
      <div className="placeholder">Waiting for service...</div>
    </section>
  )
}