import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

export default function LoginPage() {
  const navigate = useNavigate()
  const [id, setId] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(false)

  async function handleLogin() {
    setError(false)
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ id, password }),
      })
      if (res.ok) {
        const data = await res.json()
        if (data.admin_token) {
          sessionStorage.setItem('admin_token', data.admin_token)
        }
        navigate('/admin')
      } else {
        setError(true)
      }
    } catch {
      setError(true)
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen px-4">
      <div className="bg-gray-900 rounded-2xl p-8 w-full max-w-[400px]">
        <h1 className="text-center text-2xl font-bold mb-6">MyAuth Admin</h1>

        {error && (
          <div className="error-banner bg-red-900 text-red-300 px-4 py-3 rounded-lg mb-4" role="alert">
            인증 실패: 잘못된 자격증명입니다.
          </div>
        )}

        <input
          type="text"
          placeholder="admin"
          autoComplete="username"
          value={id}
          onChange={(e) => setId(e.target.value)}
          className="block w-full px-4 py-3 mb-4 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-base"
        />
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="block w-full px-4 py-3 mb-4 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-base"
        />
        <button
          type="button"
          onClick={handleLogin}
          className="block w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-base cursor-pointer"
        >
          관리자 로그인
        </button>
      </div>
    </div>
  )
}
