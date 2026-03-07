import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import StatCard from '../components/StatCard'
import SkeletonCard from '../components/SkeletonCard'

interface DashboardStats {
  clients: number
  active_sessions: number
  tokens: number
  auth_24h: number
}

interface ActivityItem {
  time: string
  action: string
  client_name: string
  type: string
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [activity, setActivity] = useState<ActivityItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    async function fetchData() {
      try {
        const [statsRes, activityRes] = await Promise.all([
          fetch('/api/admin/dashboard/stats', { credentials: 'include' }),
          fetch('/api/admin/dashboard/activity', { credentials: 'include' }),
        ])

        if (statsRes.status === 401 || activityRes.status === 401) {
          navigate('/login', { replace: true })
          return
        }

        if (!statsRes.ok || !activityRes.ok) {
          setError('데이터를 불러오는 중 오류가 발생했습니다.')
          return
        }

        const statsData = await statsRes.json()
        const activityData = await activityRes.json()

        setStats(statsData)
        setActivity(activityData)
      } catch {
        setError('서버 연결에 실패했습니다.')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [navigate])

  if (error) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div role="alert" className="text-red-400 text-center">
          {error}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <h1 className="text-xl font-bold text-white">MyAuth Admin</h1>
          <span className="text-sm text-gray-400">대시보드</span>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-4xl mx-auto px-6 py-8">
        {/* Stats section */}
        <section aria-label="통계">
          <h2 className="text-lg font-semibold text-gray-200 mb-4">통계 개요</h2>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4 mb-8">
            {loading ? (
              <>
                <SkeletonCard />
                <SkeletonCard />
                <SkeletonCard />
                <SkeletonCard />
              </>
            ) : (
              <>
                <StatCard
                  label="클라이언트"
                  value={stats?.clients ?? 0}
                  color="indigo"
                />
                <StatCard
                  label="활성 세션"
                  value={stats?.active_sessions ?? 0}
                  color="emerald"
                />
                <StatCard
                  label="토큰"
                  value={stats?.tokens ?? 0}
                  color="amber"
                />
                <StatCard
                  label="24h 인증"
                  value={stats?.auth_24h ?? 0}
                  color="sky"
                />
              </>
            )}
          </div>
        </section>

        {/* Recent activity section */}
        <section aria-label="최근 활동">
          <h2 className="text-lg font-semibold text-gray-200 mb-4">최근 활동</h2>
          <div className="bg-gray-900 rounded-xl border border-gray-800">
            {loading ? (
              <div className="p-6 text-gray-500 text-sm text-center">
                불러오는 중...
              </div>
            ) : activity.length === 0 ? (
              <ul role="list" className="divide-y divide-gray-800">
                <li className="px-6 py-4 text-gray-500 text-sm text-center">
                  최근 활동이 없습니다.
                </li>
              </ul>
            ) : (
              <ul role="list" className="divide-y divide-gray-800">
                {activity.map((item, idx) => (
                  <li key={idx} className="px-6 py-4 flex items-start gap-4">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {item.client_name}
                      </p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {item.action} · {item.type}
                      </p>
                    </div>
                    <time className="text-xs text-gray-500 whitespace-nowrap mt-0.5">
                      {new Date(item.time).toLocaleString('ko-KR')}
                    </time>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}
