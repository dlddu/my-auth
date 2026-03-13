import { useState } from 'react'

function hasLoginErrorCookie(): boolean {
  if (document.cookie.includes('login_error=1')) {
    document.cookie = 'login_error=; path=/; max-age=0'
    return true
  }
  return false
}

export default function LoginPage() {
  const [error] = useState(hasLoginErrorCookie)

  return (
    <div className="flex flex-col items-center justify-center min-h-screen px-4">
      <div className="bg-gray-900 rounded-2xl p-8 w-full max-w-[400px]">
        <h1 className="text-center text-2xl font-bold mb-6">MyAuth Admin</h1>

        {error && (
          <div className="error-banner bg-red-900 text-red-300 px-4 py-3 rounded-lg mb-4" role="alert">
            인증 실패: 잘못된 자격증명입니다.
          </div>
        )}

        <form method="POST" action="/api/admin/login">
          <input
            type="text"
            name="id"
            placeholder="admin"
            autoComplete="username"
            className="block w-full px-4 py-3 mb-4 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-base"
          />
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            className="block w-full px-4 py-3 mb-4 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-base"
          />
          <button
            type="submit"
            className="block w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-base cursor-pointer"
          >
            관리자 로그인
          </button>
        </form>
      </div>
    </div>
  )
}
