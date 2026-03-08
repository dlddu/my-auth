import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import TopHeader from '../components/TopHeader'
import BottomNav from '../components/BottomNav'
import StatCard from '../components/StatCard'
import SkeletonCard from '../components/SkeletonCard'

interface Stats {
  clients: number
  sessions: number
  tokens: number
  auth_24h: number
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/admin/stats', { credentials: 'same-origin' })
      .then((r) => {
        if (r.status === 401) {
          navigate('/admin/login')
          return null
        }
        return r.json()
      })
      .then((data) => {
        if (data) setStats(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [navigate])

  return (
    <div className="min-h-screen flex flex-col">
      <TopHeader />

      <main className="flex-1 px-4 py-4 max-w-[600px] mx-auto w-full pb-16">
        <h1 className="text-lg font-bold mb-4">대시보드</h1>

        <div className="grid grid-cols-2 gap-4 mb-6">
          {loading ? (
            <>
              <SkeletonCard />
              <SkeletonCard />
              <SkeletonCard />
              <SkeletonCard />
            </>
          ) : stats ? (
            <>
              <StatCard label="클라이언트" value={stats.clients} />
              <StatCard label="활성 세션" value={stats.sessions} />
              <StatCard label="토큰" value={stats.tokens} />
              <StatCard label="24h 인증" value={stats.auth_24h} />
            </>
          ) : null}
        </div>

        <div className="activity-section">
          <h2 className="text-base font-semibold mb-3">최근 활동</h2>
          <ul className="list-none">
            <li className="py-2 border-b border-gray-800 text-sm text-gray-300">
              시스템 시작됨
            </li>
          </ul>
        </div>
      </main>

      <BottomNav />
    </div>
  )
}
