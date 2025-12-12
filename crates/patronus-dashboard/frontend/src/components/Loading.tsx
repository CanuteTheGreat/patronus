interface LoadingProps {
  size?: 'sm' | 'md' | 'lg'
  message?: string
  fullScreen?: boolean
}

export default function Loading({ size = 'md', message, fullScreen = false }: LoadingProps) {
  const sizeClasses = {
    sm: 'h-6 w-6',
    md: 'h-12 w-12',
    lg: 'h-16 w-16',
  }

  const spinner = (
    <div
      className="flex flex-col items-center justify-center"
      role="status"
      aria-live="polite"
    >
      <div
        className={`animate-spin rounded-full border-b-2 border-blue-500 ${sizeClasses[size]}`}
        aria-hidden="true"
      />
      <span className="sr-only">Loading{message ? `: ${message}` : '...'}</span>
      {message && (
        <p className="mt-4 text-sm text-gray-600 dark:text-gray-400" aria-hidden="true">
          {message}
        </p>
      )}
    </div>
  )

  if (fullScreen) {
    return (
      <div
        className="fixed inset-0 bg-white dark:bg-gray-900 flex items-center justify-center z-50"
        aria-busy="true"
      >
        {spinner}
      </div>
    )
  }

  return (
    <div className="flex items-center justify-center py-12" aria-busy="true">
      {spinner}
    </div>
  )
}

export function LoadingOverlay({ message }: { message?: string }) {
  return (
    <div
      className="absolute inset-0 bg-white/75 dark:bg-gray-900/75 flex items-center justify-center z-10 rounded-lg"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <Loading size="md" message={message} />
    </div>
  )
}

export function LoadingSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div
      className="animate-pulse space-y-4"
      role="status"
      aria-label="Loading content"
      aria-busy="true"
    >
      <span className="sr-only">Loading content...</span>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="space-y-2" aria-hidden="true">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2" />
        </div>
      ))}
    </div>
  )
}

// Table skeleton for better data loading experience
export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div
      className="animate-pulse"
      role="status"
      aria-label="Loading table data"
      aria-busy="true"
    >
      <span className="sr-only">Loading table data...</span>
      <div className="space-y-3" aria-hidden="true">
        {/* Header */}
        <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
          {Array.from({ length: columns }).map((_, i) => (
            <div key={i} className="h-4 bg-gray-300 dark:bg-gray-600 rounded" />
          ))}
        </div>
        {/* Rows */}
        {Array.from({ length: rows }).map((_, rowIndex) => (
          <div
            key={rowIndex}
            className="grid gap-4 py-2"
            style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}
          >
            {Array.from({ length: columns }).map((_, colIndex) => (
              <div key={colIndex} className="h-4 bg-gray-200 dark:bg-gray-700 rounded" />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

// Card skeleton for card-based layouts
export function CardSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
      role="status"
      aria-label="Loading cards"
      aria-busy="true"
    >
      <span className="sr-only">Loading cards...</span>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="animate-pulse p-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700"
          aria-hidden="true"
        >
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-2/3 mb-3" />
          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-full mb-2" />
          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-4/5" />
        </div>
      ))}
    </div>
  )
}
