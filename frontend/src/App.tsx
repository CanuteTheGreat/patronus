import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './components/Dashboard'
import Sites from './components/Sites'
import Topology from './components/Topology'
import SLA from './components/SLA'
import Traffic from './components/Traffic'
import Security from './components/Security'
import Settings from './components/Settings'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="sites" element={<Sites />} />
        <Route path="topology" element={<Topology />} />
        <Route path="sla" element={<SLA />} />
        <Route path="traffic" element={<Traffic />} />
        <Route path="security" element={<Security />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  )
}

export default App
