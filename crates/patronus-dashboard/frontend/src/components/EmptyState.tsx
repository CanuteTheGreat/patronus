import { ReactNode } from 'react'
import { FolderOpenIcon } from '@heroicons/react/24/outline'

interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
}

export default function EmptyState({
  icon,
  title,
  description,
  action,
}: EmptyStateProps) {
  return (
    <div
      className="text-center py-12"
      role="status"
      aria-live="polite"
    >
      <div className="flex justify-center mb-4" aria-hidden="true">
        {icon || (
          <div className="w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
            <FolderOpenIcon className="w-8 h-8 text-gray-400" />
          </div>
        )}
      </div>
      <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
        {title}
      </h3>
      {description && (
        <p className="text-gray-500 dark:text-gray-400 mb-4 max-w-md mx-auto">
          {description}
        </p>
      )}
      {action && <div>{action}</div>}
    </div>
  )
}
