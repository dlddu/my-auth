import { useLocation, useNavigate } from 'react-router-dom'

const navItems = [
  { label: '대시보드', path: '/admin' },
  { label: '클라이언트', path: '/admin/clients' },
  { label: '로그아웃', path: '/admin/login' },
]

export default function BottomNav() {
  const location = useLocation()
  const navigate = useNavigate()

  return (
    <nav className="fixed bottom-0 left-0 right-0 bg-gray-900 border-t border-gray-800">
      <div className="max-w-[600px] mx-auto flex">
        {navItems.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={`flex-1 py-3 text-sm text-center ${
              location.pathname === item.path
                ? 'text-indigo-400 font-semibold'
                : 'text-gray-400'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </nav>
  )
}
