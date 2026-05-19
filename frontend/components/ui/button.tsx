import type { ButtonHTMLAttributes } from 'react'

import { cn } from '@/lib/utils'

export default function Button(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className, type = 'button', ...rest } = props
  return <button type={type} className={cn('rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-white hover:opacity-90', className)} {...rest} />
}
