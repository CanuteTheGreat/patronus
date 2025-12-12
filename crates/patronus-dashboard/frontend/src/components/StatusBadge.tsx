interface StatusBadgeProps {
  status: string
  size?: 'sm' | 'md'
}

const statusConfig: Record<string, { className: string; label?: string }> = {
  // Site/Path status
  Active: { className: 'badge-success' },
  Degraded: { className: 'badge-warning' },
  Down: { className: 'badge-danger' },

  // Generic status
  Enabled: { className: 'badge-success' },
  Disabled: { className: 'badge-danger' },

  // User status
  active: { className: 'badge-success', label: 'Active' },
  inactive: { className: 'badge-danger', label: 'Inactive' },

  // Policy status
  true: { className: 'badge-success', label: 'Enabled' },
  false: { className: 'badge-danger', label: 'Disabled' },
}

export default function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig[String(status)] || {
    className: 'badge-info',
  }

  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : ''
  const displayLabel = config.label || status

  return (
    <span
      className={`badge ${config.className} ${sizeClasses}`}
      role="status"
      aria-label={`Status: ${displayLabel}`}
    >
      {displayLabel}
    </span>
  )
}

export function RoleBadge({ role }: { role: string }) {
  const roleConfig: Record<string, string> = {
    Admin: 'badge-danger',
    Operator: 'badge-warning',
    Viewer: 'badge-info',
  }

  return (
    <span
      className={`badge ${roleConfig[role] || 'badge-info'}`}
      role="status"
      aria-label={`Role: ${role}`}
    >
      {role}
    </span>
  )
}

export function QualityBadge({ score }: { score: number }) {
  let className = 'badge-danger'
  let label = 'Poor'

  if (score >= 80) {
    className = 'badge-success'
    label = 'Excellent'
  } else if (score >= 60) {
    className = 'badge-info'
    label = 'Good'
  } else if (score >= 40) {
    className = 'badge-warning'
    label = 'Fair'
  }

  const scoreFormatted = score.toFixed(0)

  return (
    <span
      className={`badge ${className}`}
      role="status"
      aria-label={`Quality score: ${scoreFormatted}, rated as ${label}`}
    >
      {label} ({scoreFormatted})
    </span>
  )
}

// Severity badge for alerts
export function SeverityBadge({ severity }: { severity: 'Critical' | 'Warning' | 'Info' }) {
  const severityConfig: Record<string, { className: string; ariaLabel: string }> = {
    Critical: { className: 'badge-danger', ariaLabel: 'Critical severity' },
    Warning: { className: 'badge-warning', ariaLabel: 'Warning severity' },
    Info: { className: 'badge-info', ariaLabel: 'Informational' },
  }

  const config = severityConfig[severity] || severityConfig.Info

  return (
    <span
      className={`badge ${config.className}`}
      role="status"
      aria-label={config.ariaLabel}
    >
      {severity}
    </span>
  )
}
