import { useState, useEffect } from 'react'
import { useMutation } from '@apollo/client'
import { LOGIN, REFRESH_TOKEN } from '../graphql/queries'
import type { User, LoginResponse } from '../types'

export function useAuth() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  const [loginMutation] = useMutation(LOGIN)
  const [refreshTokenMutation] = useMutation(REFRESH_TOKEN)

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    const userData = localStorage.getItem('user')

    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData)
        setUser(parsedUser)
        setIsAuthenticated(true)
      } catch (err) {
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        localStorage.removeItem('user')
      }
    }

    setLoading(false)
  }, [])

  const login = async (email: string, password: string) => {
    try {
      const { data } = await loginMutation({
        variables: { email, password },
      })

      const response = data as LoginResponse

      localStorage.setItem('access_token', response.login.accessToken)
      localStorage.setItem('refresh_token', response.login.refreshToken)
      localStorage.setItem('user', JSON.stringify(response.login.user))

      setUser(response.login.user)
      setIsAuthenticated(true)

      return { success: true }
    } catch (err: any) {
      return {
        success: false,
        error: err.message || 'Login failed',
      }
    }
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('user')
    setUser(null)
    setIsAuthenticated(false)
    window.location.href = '/login'
  }

  const refreshToken = async () => {
    const token = localStorage.getItem('refresh_token')
    if (!token) return false

    try {
      const { data } = await refreshTokenMutation({
        variables: { refreshToken: token },
      })

      localStorage.setItem('access_token', data.refreshToken.accessToken)
      localStorage.setItem('refresh_token', data.refreshToken.refreshToken)

      return true
    } catch (err) {
      logout()
      return false
    }
  }

  return {
    user,
    loading,
    isAuthenticated,
    login,
    logout,
    refreshToken,
  }
}
