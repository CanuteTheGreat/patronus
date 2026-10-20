import { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <h1 className="text-3xl font-bold text-gray-900">{title}</h1>
      <div className="flex gap-2">{children}</div>
    </div>
  )
}

export function Card({ title, children, className }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <div className={clsx('bg-white rounded-lg shadow p-6', className)}>
      {title && <h2 className="text-lg font-semibold text-gray-900 mb-4">{title}</h2>}
      {children}
    </div>
  )
}

/** A number that always leads somewhere: every stat links to the page that explains it. */
export function Stat({ label, value, hint, to }: { label: string; value: ReactNode; hint?: string; to: string }) {
  return (
    <Link to={to} className="block bg-white rounded-lg shadow p-5 hover:ring-2 hover:ring-primary-300 transition">
      <div className="text-sm font-medium text-gray-500">{label}</div>
      <div className="mt-1 text-3xl font-bold text-gray-900">{value}</div>
      {hint && <div className="mt-1 text-xs text-gray-500">{hint}</div>}
    </Link>
  )
}

export function ErrorBanner({ error }: { error?: { message: string } | string | null }) {
  if (!error) return null
  const message = typeof error === 'string' ? error : error.message
  return (
    <div role="alert" className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
      {message}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border-2 border-dashed border-gray-200 p-8 text-center text-gray-500">{children}</div>
}

const badgeColors: Record<string, string> = {
  ACTIVE: 'bg-green-100 text-green-800',
  OPTIMAL: 'bg-green-100 text-green-800',
  Leader: 'bg-green-100 text-green-800',
  DEGRADED: 'bg-yellow-100 text-yellow-800',
  MAINTENANCE: 'bg-blue-100 text-blue-800',
  Candidate: 'bg-yellow-100 text-yellow-800',
  Follower: 'bg-gray-100 text-gray-800',
  OFFLINE: 'bg-red-100 text-red-800',
  FAILED: 'bg-red-100 text-red-800',
  unreachable: 'bg-red-100 text-red-800',
}

export function Badge({ value }: { value: string }) {
  return (
    <span className={clsx('inline-flex rounded-full px-2 py-0.5 text-xs font-semibold', badgeColors[value] ?? 'bg-gray-100 text-gray-800')}>
      {value}
    </span>
  )
}

export function Button({
  children,
  onClick,
  type = 'button',
  variant = 'primary',
  disabled,
}: {
  children: ReactNode
  onClick?: () => void
  type?: 'button' | 'submit'
  variant?: 'primary' | 'secondary' | 'danger'
  disabled?: boolean
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        'inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:opacity-50',
        variant === 'primary' && 'bg-primary-600 text-white hover:bg-primary-700',
        variant === 'secondary' && 'bg-white text-gray-700 ring-1 ring-gray-300 hover:bg-gray-50',
        variant === 'danger' && 'bg-red-600 text-white hover:bg-red-700',
      )}
    >
      {children}
    </button>
  )
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-gray-700 mb-1">{label}</span>
      {children}
    </label>
  )
}

export const inputClass =
  'w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500'

export function fmtDate(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

export function fmtNum(value: number | undefined | null, digits = 1): string {
  return value === undefined || value === null ? '—' : value.toFixed(digits)
}
