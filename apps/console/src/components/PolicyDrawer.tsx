import { Check, Plus, RotateCw, Settings2, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { intelligenceApi } from '../api/client'
import type { RelevancePolicy } from '../types'

interface PolicyDrawerProps {
  open: boolean
  onClose: () => void
  onSaved: () => void
}

export function PolicyDrawer({ open, onClose, onSaved }: PolicyDrawerProps) {
  const [policy, setPolicy] = useState<RelevancePolicy | null>(null)
  const [newVendor, setNewVendor] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setMessage(null)
    void intelligenceApi.settings().then(setPolicy).catch((error: Error) => setMessage(error.message))
  }, [open])

  if (!open) return null

  const addVendor = () => {
    if (!policy || !newVendor.trim()) return
    const vendor = newVendor.trim()
    if (!policy.vendor_keywords.some((item) => item.toLowerCase() === vendor.toLowerCase())) {
      setPolicy({ ...policy, vendor_keywords: [...policy.vendor_keywords, vendor] })
    }
    setNewVendor('')
  }

  const save = async () => {
    if (!policy) return
    setSaving(true)
    setMessage(null)
    try {
      const result = await intelligenceApi.updateSettings(policy)
      setPolicy(result.policy)
      setMessage(`策略已保存，重新判定 ${result.reclassified_count} 条记录`)
      onSaved()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '保存失败')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-sm" onMouseDown={onClose}>
      <div role="dialog" aria-modal="true" aria-labelledby="policy-title" onMouseDown={(event) => event.stopPropagation()} className="detail-enter h-full w-full max-w-[500px] overflow-y-auto border-l border-white/10 bg-[#0b1018]/98 p-6 shadow-2xl sm:p-8">
        <div className="flex items-start justify-between">
          <div>
            <div className="eyebrow"><Settings2 size={13} /> Classification policy</div>
            <h2 id="policy-title" className="mt-3 text-2xl font-semibold tracking-tight text-white">固件相关性策略</h2>
            <p className="mt-2 text-xs leading-6 text-slate-500">修改后会重新判定已有记录，不需要重新下载情报。</p>
          </div>
          <button type="button" onClick={onClose} className="icon-button" aria-label="关闭策略"><X size={18} /></button>
        </div>

        {!policy ? (
          <div className="mt-12 flex items-center gap-2 text-sm text-slate-500"><RotateCw size={16} className="animate-spin" />加载策略…</div>
        ) : (
          <div className="mt-8 space-y-8">
            <PolicyGroup
              title="固件专属厂商"
              help="仅厂商命中即可进入情报流，适合主要产品是网络或嵌入式设备的厂商。"
              values={policy.firmware_only_vendors}
              onRemove={(value) => setPolicy({ ...policy, firmware_only_vendors: policy.firmware_only_vendors.filter((item) => item !== value) })}
            />

            <div>
              <PolicyGroup
                title="关注厂商"
                help="需要同时出现设备、固件或 CPE 证据才会进入情报流。"
                values={policy.vendor_keywords}
                onRemove={(value) => setPolicy({ ...policy, vendor_keywords: policy.vendor_keywords.filter((item) => item !== value) })}
              />
              <div className="mt-3 flex gap-2">
                <input
                  value={newVendor}
                  onChange={(event) => setNewVendor(event.target.value)}
                  onKeyDown={(event) => event.key === 'Enter' && addVendor()}
                  placeholder="添加厂商关键词"
                  className="h-10 flex-1 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 text-xs text-white outline-none transition placeholder:text-slate-700 focus:border-signal/30"
                />
                <button type="button" onClick={addVendor} className="icon-button h-10 w-10"><Plus size={16} /></button>
              </div>
            </div>

            <div>
              <div className="text-xs font-semibold text-slate-300">判定阈值</div>
              <div className="mt-3 space-y-4 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
                <Threshold label="强相关" value={policy.strong_threshold} min={policy.likely_threshold} onChange={(value) => setPolicy({ ...policy, strong_threshold: value })} />
                <Threshold label="较相关" value={policy.likely_threshold} min={policy.review_threshold} max={policy.strong_threshold} onChange={(value) => setPolicy({ ...policy, likely_threshold: value })} />
              </div>
            </div>

            {message && <div className="rounded-xl border border-signal/15 bg-signal/[0.05] px-3 py-2.5 text-xs text-signal">{message}</div>}

            <button type="button" onClick={() => void save()} disabled={saving} className="flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-signal text-sm font-semibold text-[#11170a] shadow-signal transition hover:brightness-105 disabled:opacity-50">
              {saving ? <RotateCw size={16} className="animate-spin" /> : <Check size={16} />}
              保存并重新判定
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function PolicyGroup({ title, help, values, onRemove }: { title: string; help: string; values: string[]; onRemove: (value: string) => void }) {
  return (
    <div>
      <div className="text-xs font-semibold text-slate-300">{title}</div>
      <p className="mt-1 text-[11px] leading-5 text-slate-600">{help}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {values.map((value) => (
          <button key={value} type="button" onClick={() => onRemove(value)} title="点击移除" className="group flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.035] px-2.5 py-1.5 text-[11px] text-slate-400 transition hover:border-ember/20 hover:text-ember">
            {value}<X size={10} className="opacity-0 transition group-hover:opacity-100" />
          </button>
        ))}
      </div>
    </div>
  )
}

function Threshold({ label, value, min = 0, max = 100, onChange }: { label: string; value: number; min?: number; max?: number; onChange: (value: number) => void }) {
  return (
    <label className="block">
      <div className="mb-2 flex justify-between text-[11px]"><span className="text-slate-500">{label}</span><span className="font-mono text-signal">{value}</span></div>
      <input type="range" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} className="policy-range w-full" />
    </label>
  )
}
