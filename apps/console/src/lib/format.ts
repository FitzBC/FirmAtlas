export function formatRelativeTime(value: string | null, now = new Date()): string {
  if (!value) return '尚未更新'
  const date = new Date(value)
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000)
  const formatter = new Intl.RelativeTimeFormat('zh-CN', { numeric: 'auto' })
  const ranges: Array<[number, Intl.RelativeTimeFormatUnit]> = [
    [31_536_000, 'year'],
    [2_592_000, 'month'],
    [86_400, 'day'],
    [3_600, 'hour'],
    [60, 'minute'],
  ]
  for (const [size, unit] of ranges) {
    if (Math.abs(seconds) >= size) return formatter.format(Math.round(seconds / size), unit)
  }
  return formatter.format(seconds, 'second')
}

export function formatCompactNumber(value: number): string {
  return new Intl.NumberFormat('zh-CN', { notation: 'compact' }).format(value)
}

export function severityTone(severity: string | null): string {
  switch (severity) {
    case 'CRITICAL':
      return 'text-[#ff8a65] bg-[#ff8a65]/10 ring-[#ff8a65]/20'
    case 'HIGH':
      return 'text-[#ffbd70] bg-[#ffbd70]/10 ring-[#ffbd70]/20'
    case 'MEDIUM':
      return 'text-[#75d6ff] bg-[#75d6ff]/10 ring-[#75d6ff]/20'
    default:
      return 'text-slate-300 bg-white/5 ring-white/10'
  }
}
