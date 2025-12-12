import { useEffect, useRef, useCallback } from 'react'
import { ExclamationTriangleIcon, CheckCircleIcon, InformationCircleIcon } from '@heroicons/react/24/outline'

interface ConfirmModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  message: string
  confirmText?: string
  cancelText?: string
  type?: 'danger' | 'warning' | 'info' | 'success'
  variant?: 'danger' | 'warning' | 'info' | 'success' // alias for type
  loading?: boolean
}

export default function ConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  type,
  variant,
  loading = false,
}: ConfirmModalProps) {
  const modalRef = useRef<HTMLDivElement>(null)
  const cancelButtonRef = useRef<HTMLButtonElement>(null)
  const confirmButtonRef = useRef<HTMLButtonElement>(null)

  const modalVariant = type || variant || 'danger'

  // Handle escape key
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !loading) {
        onClose()
      }
    },
    [onClose, loading]
  )

  // Focus trap
  useEffect(() => {
    if (!isOpen) return

    document.addEventListener('keydown', handleKeyDown)

    // Focus the cancel button when modal opens
    cancelButtonRef.current?.focus()

    // Prevent body scroll
    document.body.style.overflow = 'hidden'

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''
    }
  }, [isOpen, handleKeyDown])

  // Handle tab key for focus trap
  const handleTabKey = (event: React.KeyboardEvent) => {
    if (event.key !== 'Tab' || !modalRef.current) return

    const focusableElements = modalRef.current.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )
    const firstElement = focusableElements[0] as HTMLElement
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement

    if (event.shiftKey) {
      if (document.activeElement === firstElement) {
        event.preventDefault()
        lastElement?.focus()
      }
    } else {
      if (document.activeElement === lastElement) {
        event.preventDefault()
        firstElement?.focus()
      }
    }
  }

  if (!isOpen) return null

  const iconMap = {
    danger: ExclamationTriangleIcon,
    warning: ExclamationTriangleIcon,
    info: InformationCircleIcon,
    success: CheckCircleIcon,
  }

  const colorMap = {
    danger: {
      bg: 'bg-red-100 dark:bg-red-900',
      icon: 'text-red-600 dark:text-red-400',
      button: 'btn-danger',
    },
    warning: {
      bg: 'bg-yellow-100 dark:bg-yellow-900',
      icon: 'text-yellow-600 dark:text-yellow-400',
      button: 'bg-yellow-600 text-white hover:bg-yellow-700 focus:ring-yellow-500',
    },
    info: {
      bg: 'bg-blue-100 dark:bg-blue-900',
      icon: 'text-blue-600 dark:text-blue-400',
      button: 'btn-primary',
    },
    success: {
      bg: 'bg-green-100 dark:bg-green-900',
      icon: 'text-green-600 dark:text-green-400',
      button: 'bg-green-600 text-white hover:bg-green-700 focus:ring-green-500',
    },
  }

  const Icon = iconMap[modalVariant]
  const colors = colorMap[modalVariant]

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      onClick={loading ? undefined : onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      aria-describedby="modal-description"
    >
      <div
        ref={modalRef}
        className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleTabKey}
      >
        <div className="flex items-start space-x-4">
          <div
            className={`flex-shrink-0 w-12 h-12 rounded-full ${colors.bg} flex items-center justify-center`}
            aria-hidden="true"
          >
            <Icon className={`w-6 h-6 ${colors.icon}`} />
          </div>
          <div className="flex-1">
            <h3
              id="modal-title"
              className="text-lg font-semibold text-gray-900 dark:text-gray-100"
            >
              {title}
            </h3>
            <p
              id="modal-description"
              className="mt-2 text-sm text-gray-600 dark:text-gray-400"
            >
              {message}
            </p>
          </div>
        </div>
        <div className="mt-6 flex justify-end space-x-3">
          <button
            ref={cancelButtonRef}
            type="button"
            onClick={onClose}
            disabled={loading}
            className="btn btn-secondary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 dark:focus:ring-offset-gray-800"
          >
            {cancelText}
          </button>
          <button
            ref={confirmButtonRef}
            type="button"
            onClick={onConfirm}
            disabled={loading}
            className={`btn ${colors.button} focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-gray-800`}
            aria-busy={loading}
          >
            {loading ? (
              <>
                <span className="sr-only">Processing...</span>
                <span aria-hidden="true">Processing...</span>
              </>
            ) : (
              confirmText
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
