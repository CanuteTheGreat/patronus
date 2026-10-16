import { Routes, Route, Navigate, Outlet } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './components/Dashboard'
import Sites from './components/Sites'
import Topology from './components/Topology'
import SLA from './components/SLA'
import Traffic from './components/Traffic'
import Security from './components/Security'
import Settings from './components/Settings'
import Cluster from './components/Cluster'
import Login from './components/Login'
import { isLoggedIn } from './auth'

function RequireAuth() {
  return isLoggedIn() ? <Outlet /> : <Navigate to="/login" replace />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="sites" element={<Sites />} />
          <Route path="topology" element={<Topology />} />
          <Route path="sla" element={<SLA />} />
          <Route path="traffic" element={<Traffic />} />
          <Route path="security" element={<Security />} />
          <Route path="cluster" element={<Cluster />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Route>
    </Routes>
  )
}

export default App
