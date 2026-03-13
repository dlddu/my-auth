import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import TopHeader from '../components/TopHeader'
import BottomNav from '../components/BottomNav'

interface Client {
  id: string
  client_secret?: string
  redirect_uris: string[]
  grant_types: string[]
  response_types: string[]
  scopes: string[]
  is_public: boolean
  token_endpoint_auth_method: string
}

interface CreateClientInput {
  id: string
  redirect_uris: string[]
  grant_types: string[]
  response_types: string[]
  scopes: string[]
  is_public: boolean
  token_endpoint_auth_method: string
}

const GRANT_TYPE_OPTIONS = [
  { value: 'authorization_code', label: 'authorization_code' },
  { value: 'client_credentials', label: 'client_credentials' },
  { value: 'refresh_token', label: 'refresh_token' },
  { value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'device_code' },
]

const RESPONSE_TYPE_OPTIONS = [
  { value: 'code', label: 'code' },
  { value: 'token', label: 'token' },
]

// SkeletonCard for loading state
function SkeletonClientCard() {
  return (
    <div className="bg-gray-900 rounded-xl p-4 animate-pulse">
      <div className="h-4 w-48 bg-gray-700 rounded mb-2" />
      <div className="h-3 w-32 bg-gray-700 rounded" />
    </div>
  )
}

// ClientCard component
interface ClientCardProps {
  client: Client
  expanded: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}

function ClientCard({ client, expanded, onToggle, onEdit, onDelete }: ClientCardProps) {
  return (
    <div
      data-testid="client-card"
      className="client-card bg-gray-900 rounded-xl border border-gray-800 overflow-hidden"
      role="listitem"
    >
      <button
        className="w-full px-4 py-3 flex items-center justify-between text-left"
        onClick={onToggle}
        aria-label="상세 보기"
      >
        <div className="min-w-0 flex-1">
          <span className="font-mono text-sm text-gray-100 truncate block">{client.id}</span>
          <span className="text-xs text-gray-400 truncate block">{client.grant_types.join(', ')}</span>
        </div>
        <span className="ml-2 text-gray-400 text-xs flex-shrink-0">{expanded ? '▲' : '▼'}</span>
      </button>

      {expanded && (
        <div
          data-testid="client-detail"
          className="client-detail px-4 pb-4 border-t border-gray-800"
        >
          <div className="mt-3 space-y-2 text-sm">
            <div>
              <span className="text-gray-400">Redirect URIs: </span>
              <span className="text-gray-200">{client.redirect_uris.join(', ') || '-'}</span>
            </div>
            <div>
              <span className="text-gray-400">Grant Types: </span>
              <span className="text-gray-200">{client.grant_types.join(', ') || '-'}</span>
            </div>
            <div>
              <span className="text-gray-400">Response Types: </span>
              <span className="text-gray-200">{client.response_types.join(', ') || '-'}</span>
            </div>
            <div>
              <span className="text-gray-400">Scopes: </span>
              <span className="text-gray-200">{client.scopes.join(', ') || '-'}</span>
            </div>
            <div>
              <span className="text-gray-400">Public: </span>
              <span className="text-gray-200">{client.is_public ? '예' : '아니오'}</span>
            </div>
            <div>
              <span className="text-gray-400">Auth Method: </span>
              <span className="text-gray-200">{client.token_endpoint_auth_method}</span>
            </div>
          </div>

          <div className="mt-4 flex gap-2">
            <button
              onClick={onEdit}
              className="flex-1 py-2 bg-gray-800 hover:bg-gray-700 text-gray-100 rounded-lg text-sm"
              aria-label="편집"
            >
              편집
            </button>
            <button
              onClick={onDelete}
              className="flex-1 py-2 bg-red-900 hover:bg-red-800 text-red-200 rounded-lg text-sm"
              aria-label="삭제"
            >
              삭제
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// CreateClientSheet component
interface CreateClientSheetProps {
  onClose: () => void
  onCreate: (input: CreateClientInput) => void
}

function CreateClientSheet({ onClose, onCreate }: CreateClientSheetProps) {
  const [clientId, setClientId] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [grantTypes, setGrantTypes] = useState<string[]>([])
  const [responseTypes, setResponseTypes] = useState<string[]>([])
  const [scopes, setScopes] = useState('')
  const [isPublic, setIsPublic] = useState(false)

  function toggleArray(arr: string[], value: string): string[] {
    return arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value]
  }

  function handleSubmit() {
    const input: CreateClientInput = {
      id: clientId,
      redirect_uris: redirectUri ? [redirectUri] : [],
      grant_types: grantTypes,
      response_types: responseTypes,
      scopes: scopes ? scopes.split(' ').filter(Boolean) : [],
      is_public: isPublic,
      token_endpoint_auth_method: isPublic ? 'none' : 'client_secret_basic',
    }
    onCreate(input)
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-gray-950 flex flex-col fullscreen-sheet sheet"
      data-testid="client-sheet"
      role="dialog"
      aria-modal="true"
      aria-label="새 클라이언트"
    >
      {/* iOS-style header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900">
        <button
          onClick={onClose}
          className="text-indigo-400 text-sm"
          aria-label="취소"
        >
          취소
        </button>
        <span className="text-gray-100 font-semibold">새 클라이언트</span>
        <button
          onClick={handleSubmit}
          className="text-indigo-400 text-sm font-semibold"
          aria-label="생성"
        >
          생성
        </button>
      </div>

      {/* Form body */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1" htmlFor="create-client-id">
            Client ID
          </label>
          <input
            id="create-client-id"
            type="text"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            className="block w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-sm"
            placeholder="my-client"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1" htmlFor="create-redirect-uri">
            Redirect URI
          </label>
          <input
            id="create-redirect-uri"
            type="text"
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
            className="block w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-sm"
            placeholder="https://example.com/callback"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-2">Grant Type</label>
          <div className="space-y-2">
            {GRANT_TYPE_OPTIONS.map((opt) => (
              <label key={opt.value} className="flex items-center gap-2 text-sm text-gray-200">
                <input
                  type="checkbox"
                  name={opt.value}
                  checked={grantTypes.includes(opt.value)}
                  onChange={() => setGrantTypes(toggleArray(grantTypes, opt.value))}
                  className="rounded"
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-2">Response Type</label>
          <div className="space-y-2">
            {RESPONSE_TYPE_OPTIONS.map((opt) => (
              <label key={opt.value} className="flex items-center gap-2 text-sm text-gray-200">
                <input
                  type="checkbox"
                  name={opt.value}
                  checked={responseTypes.includes(opt.value)}
                  onChange={() => setResponseTypes(toggleArray(responseTypes, opt.value))}
                  className="rounded"
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1" htmlFor="create-scopes">
            Scopes
          </label>
          <input
            id="create-scopes"
            type="text"
            name="scopes"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            className="block w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-sm"
            placeholder="openid profile email"
          />
        </div>

        <div>
          <label className="flex items-center gap-2 text-sm text-gray-200">
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
              className="rounded"
            />
            Public Client
          </label>
        </div>
      </div>
    </div>
  )
}

// EditClientSheet component
interface EditClientSheetProps {
  client: Client
  onClose: () => void
  onSave: (input: CreateClientInput) => void
}

function EditClientSheet({ client, onClose, onSave }: EditClientSheetProps) {
  const [redirectUri, setRedirectUri] = useState(client.redirect_uris[0] || '')
  const [grantTypes, setGrantTypes] = useState<string[]>(client.grant_types)
  const [responseTypes, setResponseTypes] = useState<string[]>(client.response_types)
  const [scopes, setScopes] = useState(client.scopes.join(' '))
  const [isPublic, setIsPublic] = useState(client.is_public)

  function toggleArray(arr: string[], value: string): string[] {
    return arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value]
  }

  function handleSubmit() {
    const input: CreateClientInput = {
      id: client.id,
      redirect_uris: redirectUri ? [redirectUri] : [],
      grant_types: grantTypes,
      response_types: responseTypes,
      scopes: scopes ? scopes.split(' ').filter(Boolean) : [],
      is_public: isPublic,
      token_endpoint_auth_method: isPublic ? 'none' : 'client_secret_basic',
    }
    onSave(input)
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-gray-950 flex flex-col edit-sheet edit-form"
      data-testid="client-edit-sheet"
      role="dialog"
      aria-modal="true"
      aria-label="클라이언트 편집"
    >
      {/* iOS-style header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900">
        <button
          onClick={onClose}
          className="text-indigo-400 text-sm"
          aria-label="취소"
        >
          취소
        </button>
        <span className="text-gray-100 font-semibold">클라이언트 편집</span>
        <button
          onClick={handleSubmit}
          className="text-indigo-400 text-sm font-semibold"
          aria-label="저장"
        >
          저장
        </button>
      </div>

      {/* Form body */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Client ID</label>
          <div className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 text-sm">
            {client.id}
          </div>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1" htmlFor="edit-redirect-uri">
            Redirect URI
          </label>
          <input
            id="edit-redirect-uri"
            type="text"
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
            className="block w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-sm"
            placeholder="https://example.com/callback"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-2">Grant Type</label>
          <div className="space-y-2">
            {GRANT_TYPE_OPTIONS.map((opt) => (
              <label key={opt.value} className="flex items-center gap-2 text-sm text-gray-200">
                <input
                  type="checkbox"
                  name={opt.value}
                  checked={grantTypes.includes(opt.value)}
                  onChange={() => setGrantTypes(toggleArray(grantTypes, opt.value))}
                  className="rounded"
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-2">Response Type</label>
          <div className="space-y-2">
            {RESPONSE_TYPE_OPTIONS.map((opt) => (
              <label key={opt.value} className="flex items-center gap-2 text-sm text-gray-200">
                <input
                  type="checkbox"
                  name={opt.value}
                  checked={responseTypes.includes(opt.value)}
                  onChange={() => setResponseTypes(toggleArray(responseTypes, opt.value))}
                  className="rounded"
                />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1" htmlFor="edit-scopes">
            Scopes
          </label>
          <input
            id="edit-scopes"
            type="text"
            name="scopes"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            className="block w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-50 text-sm"
            placeholder="openid profile email"
          />
        </div>

        <div>
          <label className="flex items-center gap-2 text-sm text-gray-200">
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
              className="rounded"
            />
            Public Client
          </label>
        </div>
      </div>
    </div>
  )
}

// ConfirmDialog component
interface ConfirmDialogProps {
  message: string
  onConfirm: () => void
  onCancel: () => void
}

function ConfirmDialog({ message, onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="confirm-dialog"
      role="alertdialog"
      aria-modal="true"
      aria-label="삭제 확인"
    >
      <div className="bg-gray-900 rounded-xl p-6 mx-4 w-full max-w-sm border border-gray-800">
        <p className="text-gray-100 text-sm mb-6">{message}</p>
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-sm"
            aria-label="취소"
          >
            취소
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm"
            aria-label="확인"
          >
            확인
          </button>
        </div>
      </div>
    </div>
  )
}

// ClientSecretDisplay component
interface ClientSecretDisplayProps {
  secret: string
  onClose: () => void
}

function ClientSecretDisplay({ secret, onClose }: ClientSecretDisplayProps) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard not available
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      aria-modal="true"
      aria-label="클라이언트 시크릿"
    >
      <div
        data-testid="client-secret-display"
        className="bg-gray-900 rounded-xl p-6 mx-4 w-full max-w-sm border border-gray-800"
      >
        <h2 className="text-gray-100 font-semibold mb-1">클라이언트 시크릿</h2>
        <p className="text-gray-400 text-xs mb-4">
          이 시크릿은 한 번만 표시됩니다. 안전한 곳에 저장하세요.
        </p>
        <div
          data-testid="secret-value"
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 font-mono text-xs text-green-300 break-all mb-4"
        >
          {secret}
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleCopy}
            className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm"
            aria-label="복사"
          >
            {copied ? '복사됨' : '복사'}
          </button>
          <button
            onClick={onClose}
            className="flex-1 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-sm"
            aria-label="닫기"
          >
            닫기
          </button>
        </div>
      </div>
    </div>
  )
}

// Main ClientsPage
export default function ClientsPage() {
  const navigate = useNavigate()
  const [clients, setClients] = useState<Client[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editClient, setEditClient] = useState<Client | null>(null)
  const [deleteClient, setDeleteClient] = useState<Client | null>(null)
  const [secretInfo, setSecretInfo] = useState<{ id: string; secret: string } | null>(null)

  const fetchClients = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/clients', {
        credentials: 'same-origin',
      })
      if (res.status === 401) {
        navigate('/admin/login')
        return
      }
      if (!res.ok) {
        setError('클라이언트 목록을 불러오는데 실패했습니다.')
        setLoading(false)
        return
      }
      const data = await res.json()
      setClients(Array.isArray(data) ? data : [])
      setLoading(false)
    } catch {
      setError('네트워크 오류가 발생했습니다.')
      setLoading(false)
    }
  }, [navigate])

  useEffect(() => {
    fetch('/api/admin/clients', {
      credentials: 'same-origin',
    })
      .then((res) => {
        if (res.status === 401) {
          navigate('/admin/login')
          return null
        }
        if (!res.ok) {
          setError('클라이언트 목록을 불러오는데 실패했습니다.')
          setLoading(false)
          return null
        }
        return res.json()
      })
      .then((data) => {
        if (data) {
          setClients(Array.isArray(data) ? data : [])
          setLoading(false)
        }
      })
      .catch(() => {
        setError('네트워크 오류가 발생했습니다.')
        setLoading(false)
      })
  }, [navigate])

  async function handleCreate(input: CreateClientInput) {
    try {
      const res = await fetch('/api/admin/clients', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(input),
      })
      if (res.status === 401) {
        navigate('/admin/login')
        return
      }
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        setError(errData.error || '클라이언트 생성에 실패했습니다.')
        return
      }
      const created: Client = await res.json()
      setShowCreate(false)
      if (created.client_secret) {
        setSecretInfo({ id: created.id, secret: created.client_secret })
      }
      await fetchClients()
    } catch {
      setError('네트워크 오류가 발생했습니다.')
    }
  }

  async function handleSave(input: CreateClientInput) {
    if (!editClient) return
    try {
      const res = await fetch(`/api/admin/clients/${editClient.id}`, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(input),
      })
      if (res.status === 401) {
        navigate('/admin/login')
        return
      }
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        setError(errData.error || '클라이언트 수정에 실패했습니다.')
        return
      }
      setEditClient(null)
      await fetchClients()
    } catch {
      setError('네트워크 오류가 발생했습니다.')
    }
  }

  async function handleDelete() {
    if (!deleteClient) return
    try {
      const res = await fetch(`/api/admin/clients/${deleteClient.id}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      })
      if (res.status === 401) {
        navigate('/admin/login')
        return
      }
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        setError(errData.error || '클라이언트 삭제에 실패했습니다.')
        setDeleteClient(null)
        return
      }
      setDeleteClient(null)
      setExpandedId(null)
      await fetchClients()
    } catch {
      setError('네트워크 오류가 발생했습니다.')
      setDeleteClient(null)
    }
  }

  return (
    <div className="min-h-screen flex flex-col">
      <TopHeader />

      <main className="flex-1 px-4 py-4 max-w-[600px] mx-auto w-full pb-16">
        {/* Error toast */}
        {error && (
          <div
            className="fixed top-4 left-1/2 -translate-x-1/2 bg-red-900 text-red-300 px-4 py-3 rounded-lg z-50"
            role="alert"
          >
            {error}
            <button
              className="ml-3 text-red-400 hover:text-red-200"
              onClick={() => setError('')}
              aria-label="닫기"
            >
              ×
            </button>
          </div>
        )}

        <div className="flex items-center justify-between mb-4">
          <h1 className="text-lg font-bold">클라이언트</h1>
          {!showCreate && (
            <button
              onClick={() => setShowCreate(true)}
              className="px-3 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm"
              aria-label="클라이언트 추가"
            >
              클라이언트 추가
            </button>
          )}
        </div>

        {/* Loading state */}
        {loading && (
          <div className="space-y-3">
            <SkeletonClientCard />
            <SkeletonClientCard />
            <SkeletonClientCard />
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && clients.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <p className="text-gray-400 mb-4">등록된 클라이언트가 없습니다</p>
            {!showCreate && (
              <button
                onClick={() => setShowCreate(true)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm"
                aria-label="클라이언트 추가"
              >
                클라이언트 추가
              </button>
            )}
          </div>
        )}

        {/* Client list */}
        {!loading && clients.length > 0 && (
          <div className="space-y-3">
            {clients.map((client) => (
              <ClientCard
                key={client.id}
                client={client}
                expanded={expandedId === client.id}
                onToggle={() => setExpandedId(expandedId === client.id ? null : client.id)}
                onEdit={() => setEditClient(client)}
                onDelete={() => { setDeleteClient(client); setExpandedId(null); }}
              />
            ))}
          </div>
        )}
      </main>

      <BottomNav />

      {/* Client Secret Display (after creation) */}
      {secretInfo && (
        <ClientSecretDisplay
          secret={secretInfo.secret}
          onClose={() => setSecretInfo(null)}
        />
      )}

      {/* Create Client Sheet */}
      {showCreate && (
        <CreateClientSheet
          onClose={() => setShowCreate(false)}
          onCreate={handleCreate}
        />
      )}

      {/* Edit Client Sheet */}
      {editClient && (
        <EditClientSheet
          client={editClient}
          onClose={() => setEditClient(null)}
          onSave={handleSave}
        />
      )}

      {/* Confirm Delete Dialog */}
      {deleteClient && (
        <ConfirmDialog
          message="이 클라이언트를 삭제하시겠습니까?"
          onConfirm={handleDelete}
          onCancel={() => setDeleteClient(null)}
        />
      )}
    </div>
  )
}
