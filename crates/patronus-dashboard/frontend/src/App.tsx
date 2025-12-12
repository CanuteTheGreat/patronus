import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import Layout from './components/Layout'
import SkipLink from './components/SkipLink'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Sites from './pages/Sites'
import Policies from './pages/Policies'
import Metrics from './pages/Metrics'
import Topology from './pages/Topology'
import Users from './pages/Users'
import Settings from './pages/Settings'

function App() {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        role="status"
        aria-label="Loading application"
      >
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" aria-hidden="true"></div>
        <span className="sr-only">Loading...</span>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <>
      <SkipLink />
      <Layout>
        <main id="main-content" tabIndex={-1} className="outline-none">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sites" element={<Sites />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/users" element={<Users />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </Layout>
    </>
  )
}

export default App
