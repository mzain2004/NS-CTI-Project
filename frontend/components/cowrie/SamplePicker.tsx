import type { CowrieSample } from '@shared/types'

interface SamplePickerProps {
  samples: CowrieSample[]
}

export default function SamplePicker({ samples }: SamplePickerProps) {
  const safeSamples = Array.isArray(samples) ? samples : []

  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Sample Picker</h3>
      <ul className="mt-3 space-y-2 text-sm">
        {safeSamples.map((sample, index) => (
          <li key={sample.sha256 ?? `sample-${index}`} className="rounded-md border border-(--surface-border) p-2 font-mono">
            {sample.filename ?? 'Unknown sample'}
          </li>
        ))}
      </ul>
    </section>
  )
}