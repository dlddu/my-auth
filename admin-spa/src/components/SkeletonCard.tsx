export default function SkeletonCard() {
  return (
    <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-4 flex flex-col gap-2 animate-pulse">
      <div className="h-3 bg-gray-700 rounded w-16" />
      <div className="h-8 bg-gray-700 rounded w-12 mt-1" />
    </div>
  )
}
