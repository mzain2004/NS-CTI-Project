import type { GroqAnalysis } from '@shared/types'

interface MitrePanelProps {
  groq: GroqAnalysis | null
}

export default function MitrePanel({ groq }: MitrePanelProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">MITRE ATT&CK Mapping</h3>
      <ul className="mt-3 list-disc pl-4 text-sm">
        {(groq?.mitre_techniques ?? []).map((technique) => (
          <li key={technique.technique_id}>
            {technique.technique_id} - {technique.technique_name}
          </li>
        ))}
      </ul>
    </section>
  )
}