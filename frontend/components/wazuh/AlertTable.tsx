import type { WazuhAlert } from '@shared/types'

interface AlertTableProps {
  alerts: WazuhAlert[]
}

export default function AlertTable({ alerts }: AlertTableProps) {
  const safeAlerts = Array.isArray(alerts) ? alerts : []

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Wazuh Alerts</h3>
      <table className="mt-3 w-full text-sm">
        <thead>
          <tr>
            <th className="text-left">Rule</th>
            <th className="text-left">Severity</th>
            <th className="text-left">Agent</th>
          </tr>
        </thead>
        <tbody>
          {safeAlerts.map((alert, index) => (
            <tr key={alert.alert_id ?? `alert-${index}`}>
              <td className="py-2">{alert.rule_description ?? 'Unknown rule'}</td>
              <td className="py-2">{alert.severity ?? 'unknown'}</td>
              <td className="py-2">{alert.agent_name ?? 'Unknown agent'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}