import type { CowrieSample } from '@shared/types'

interface SamplePickerProps {
  samples: CowrieSample[]
}

export default function SamplePicker({ samples }: SamplePickerProps) {
  return (
    <section className="panel p-4">
      <h3 className="font-semibold">Sample Picker</h3>
      <ul className="mt-3 space-y-2 text-sm">
        {samples.map((sample) => (
          <li key={sample.sha256} className="rounded-md border border-(--surface-border) p-2 font-mono">
            {sample.filename}
          </li>
        ))}
      </ul>
    </section>
  )
}