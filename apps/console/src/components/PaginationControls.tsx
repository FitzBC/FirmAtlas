import { ChevronLeft, ChevronRight } from 'lucide-react'
import { FormEvent, useEffect, useId, useState } from 'react'

interface PaginationControlsProps {
  page: number
  pages: number
  total: number
  hasPrevious: boolean
  hasNext: boolean
  onPage: (page: number) => void
  disabled?: boolean
  detail?: string
}

export function PaginationControls({
  page, pages, total, hasPrevious, hasNext, onPage, disabled = false, detail,
}: PaginationControlsProps) {
  const [target, setTarget] = useState(String(page))
  const inputId = useId()
  useEffect(() => setTarget(String(page)), [page])

  const jump = (event: FormEvent) => {
    event.preventDefault()
    const parsed = Number.parseInt(target, 10)
    if (!Number.isFinite(parsed) || pages < 1) return
    onPage(Math.min(pages, Math.max(1, parsed)))
  }

  return (
    <div className="flex flex-col gap-3 border-t border-white/[0.065] bg-black/10 px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-[9px] text-slate-600">
        第 <strong className="font-mono font-medium text-slate-300">{page}</strong> / {pages || 1} 页 · 共 {total} 条
        {detail && <span className="ml-2">{detail}</span>}
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" disabled={!hasPrevious || disabled} onClick={() => onPage(page - 1)} className="filter-button h-8 disabled:cursor-not-allowed disabled:opacity-30">
          <ChevronLeft size={13} /> 上一页
        </button>
        <form aria-label="跳转分页" onSubmit={jump} className="flex h-8 items-center rounded-lg border border-white/[0.08] bg-black/15 pl-2 text-[9px] text-slate-600 focus-within:border-signal/30">
          <label htmlFor={inputId} className="whitespace-nowrap">跳转</label>
          <input id={inputId} aria-label="跳转页码" inputMode="numeric" min={1} max={Math.max(1, pages)} value={target} onChange={(event) => setTarget(event.target.value)} className="h-full w-10 bg-transparent px-1 text-center font-mono text-slate-300 outline-none" />
          <button type="submit" disabled={disabled || pages < 1} className="h-full border-l border-white/[0.07] px-2 text-slate-500 transition hover:text-signal disabled:opacity-30">GO</button>
        </form>
        <button type="button" disabled={!hasNext || disabled} onClick={() => onPage(page + 1)} className="filter-button h-8 disabled:cursor-not-allowed disabled:opacity-30">
          下一页 <ChevronRight size={13} />
        </button>
      </div>
    </div>
  )
}
