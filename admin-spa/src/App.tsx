import { Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ClientsPage from './pages/ClientsPage'

export default function App() {
  return (
    <Routes>
      <Route path="/admin/login" element={<LoginPage />} />
      <Route path="/admin" element={<DashboardPage />} />
      <Route path="/admin/clients" element={<ClientsPage />} />
      <Route path="*" element={<Navigate to="/admin/login" replace />} />
    </Routes>
  )
}
