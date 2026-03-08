interface StatCardProps {
  label: string
  value: number | string
}

export default function StatCard({ label, value }: StatCardProps) {
  return (
    <div className="stat-card bg-gray-900 rounded-xl p-4">
      <div className="text-sm text-gray-400">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
  )
}
