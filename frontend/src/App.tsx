import { useEffect, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { accessToken, onSessionChange } from './api'
import Layout from './components/Layout'
import Login from './components/Login'
import Dashboard from './components/Dashboard'
import Sites from './components/Sites'
import Paths from './components/Paths'
import Policies from './components/Policies'
import Traffic from './components/Traffic'
import Security from './components/Security'
import Cluster from './components/Cluster'
import Account from './components/Account'

function App() {
  const [signedIn, setSignedIn] = useState(() => accessToken() !== null)
  useEffect(() => onSessionChange(() => setSignedIn(accessToken() !== null)), [])

  if (!signedIn) return <Login />

  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="sites" element={<Sites />} />
        <Route path="paths" element={<Paths />} />
        <Route path="policies" element={<Policies />} />
        <Route path="traffic" element={<Traffic />} />
        <Route path="security" element={<Security />} />
        <Route path="cluster" element={<Cluster />} />
        <Route path="account" element={<Account />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}

export default App
