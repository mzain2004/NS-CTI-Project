import type { WazuhAlert } from '@shared/types'

interface AlertTableProps {
  alerts: WazuhAlert[]
}

export default function AlertTable({ alerts }: AlertTableProps) {
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
          {alerts.map((alert) => (
            <tr key={alert.alert_id}>
              <td className="py-2">{alert.rule_description}</td>
              <td className="py-2">{alert.severity}</td>
              <td className="py-2">{alert.agent_name}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}