interface StatCardProps {
  label: string
  value: number
  color: 'indigo' | 'emerald' | 'amber' | 'sky'
}

const colorMap = {
  indigo: {
    bg: 'bg-indigo-900/30',
    border: 'border-indigo-800/50',
    text: 'text-indigo-400',
    value: 'text-indigo-100',
  },
  emerald: {
    bg: 'bg-emerald-900/30',
    border: 'border-emerald-800/50',
    text: 'text-emerald-400',
    value: 'text-emerald-100',
  },
  amber: {
    bg: 'bg-amber-900/30',
    border: 'border-amber-800/50',
    text: 'text-amber-400',
    value: 'text-amber-100',
  },
  sky: {
    bg: 'bg-sky-900/30',
    border: 'border-sky-800/50',
    text: 'text-sky-400',
    value: 'text-sky-100',
  },
}

export default function StatCard({ label, value, color }: StatCardProps) {
  const c = colorMap[color]

  return (
    <div
      className={`${c.bg} ${c.border} border rounded-xl p-4 flex flex-col gap-1`}
      aria-label={label}
    >
      <span className={`text-xs font-medium ${c.text} uppercase tracking-wide`}>
        {label}
      </span>
      <span className={`text-3xl font-bold ${c.value}`}>{value}</span>
    </div>
  )
}
