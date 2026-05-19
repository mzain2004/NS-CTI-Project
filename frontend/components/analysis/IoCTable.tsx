import type { IoCs } from '@shared/types'

interface IoCTableProps {
  iocs: IoCs | null
}

export default function IoCTable({ iocs }: IoCTableProps) {
  const rows = [
    { key: 'IPs', values: iocs?.ips ?? [] },
    { key: 'Domains', values: iocs?.domains ?? [] },
    { key: 'URLs', values: iocs?.urls ?? [] },
    { key: 'Hashes', values: iocs?.hashes ?? [] },
  ]

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">IoCs</h3>
      <table className="mt-3 w-full text-sm">
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="w-40 py-2 font-medium">{row.key}</td>
              <td className="py-2 font-mono">{row.values.join(', ') || 'None'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}