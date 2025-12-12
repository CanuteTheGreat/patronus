import { useState, useEffect, useRef, useId } from 'react'
import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/24/outline'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  debounceMs?: number
  className?: string
  label?: string
  id?: string
}

export default function SearchInput({
  value,
  onChange,
  placeholder = 'Search...',
  debounceMs = 300,
  className = '',
  label,
  id: providedId,
}: SearchInputProps) {
  const [localValue, setLocalValue] = useState(value)
  const inputRef = useRef<HTMLInputElement>(null)
  const generatedId = useId()
  const inputId = providedId || `search-${generatedId}`

  useEffect(() => {
    setLocalValue(value)
  }, [value])

  useEffect(() => {
    const timer = setTimeout(() => {
      if (localValue !== value) {
        onChange(localValue)
      }
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [localValue, debounceMs, onChange, value])

  const handleClear = () => {
    setLocalValue('')
    onChange('')
    inputRef.current?.focus()
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      handleClear()
    }
  }

  return (
    <div className={`relative ${className}`} role="search">
      {label && (
        <label htmlFor={inputId} className="sr-only">
          {label}
        </label>
      )}
      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
      </div>
      <input
        ref={inputRef}
        id={inputId}
        type="search"
        value={localValue}
        onChange={(e) => setLocalValue(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        className="block w-full pl-10 pr-10 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        aria-label={label || 'Search'}
        autoComplete="off"
        spellCheck="false"
      />
      {localValue && (
        <button
          type="button"
          onClick={handleClear}
          className="absolute inset-y-0 right-0 pr-3 flex items-center focus:outline-none"
          aria-label="Clear search"
        >
          <XMarkIcon
            className="h-5 w-5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            aria-hidden="true"
          />
        </button>
      )}
    </div>
  )
}
