import type { ReactNode } from 'react'

interface CardProps {
  title: string
  subtitle?: string
  children: ReactNode
}

export default function Card({ title, subtitle, children }: CardProps) {
  return (
    <section className="panel p-4">
      <div className="mb-3">
        <h3 className="font-semibold">{title}</h3>
        {subtitle ? <p className="text-sm text-muted">{subtitle}</p> : null}
      </div>
      {children}
    </section>
  )
}
