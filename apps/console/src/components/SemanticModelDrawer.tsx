import { BrainCircuit, Check, KeyRound, LoaderCircle, PlugZap, Save, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { intelligenceApi } from '../api/client'
import type { SemanticModelSettings } from '../types'

interface SemanticModelDrawerProps {
  open: boolean
  onClose: () => void
  onSaved: () => void
}

export function SemanticModelDrawer({ open, onClose, onSaved }: SemanticModelDrawerProps) {
  const [settings, setSettings] = useState<SemanticModelSettings | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [models, setModels] = useState<string[]>([])
  const [busy, setBusy] = useState<'save' | 'test' | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setMessage(null)
    setApiKey('')
    void intelligenceApi.semanticSettings().then(setSettings).catch((error: Error) => setMessage(error.message))
  }, [open])

  if (!open) return null

  const test = async () => {
    if (!settings) return
    setBusy('test'); setMessage(null)
    try {
      const result = await intelligenceApi.testSemanticModel({ base_url: settings.base_url, model: settings.model, api_key: apiKey })
      setModels(result.models)
      setMessage(`连接成功，发现 ${result.models.length} 个模型`)
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : '连接失败')
    } finally { setBusy(null) }
  }

  const save = async () => {
    if (!settings) return
    setBusy('save'); setMessage(null)
    try {
      const result = await intelligenceApi.updateSemanticSettings({ ...settings, api_key: apiKey || undefined })
      setSettings(result); setApiKey('')
      setMessage('模型配置已保存；新的模型或提示词会生成新的缓存指纹')
      onSaved()
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : '保存失败')
    } finally { setBusy(null) }
  }

  return <div className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-sm" onMouseDown={onClose}><div role="dialog" aria-modal="true" aria-labelledby="semantic-settings-title" onMouseDown={(event) => event.stopPropagation()} className="detail-enter h-full w-full max-w-[520px] overflow-y-auto border-l border-white/10 bg-[#0b1018]/98 p-6 shadow-2xl sm:p-8"><div className="flex items-start justify-between"><div><div className="eyebrow"><BrainCircuit size={13} /> Local model adapter</div><h2 id="semantic-settings-title" className="mt-3 text-2xl font-semibold text-white">二次分析模型配置</h2><p className="mt-2 text-xs leading-6 text-slate-500">兼容 OpenAI Chat Completions。密钥仅保存在本地数据库，不会回传到浏览器。</p></div><button type="button" onClick={onClose} className="icon-button" aria-label="关闭模型配置"><X size={18} /></button></div>{!settings ? <div className="mt-12 flex items-center gap-2 text-sm text-slate-500"><LoaderCircle size={16} className="animate-spin" />加载配置…</div> : <div className="mt-8 space-y-6"><label className="flex items-center justify-between rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4"><div><div className="text-xs font-medium text-slate-300">启用模型增强</div><p className="mt-1 text-[10px] text-slate-600">关闭时仍会使用确定性规则完成全库提取</p></div><input type="checkbox" checked={settings.enabled} onChange={(event) => setSettings({ ...settings, enabled: event.target.checked })} className="h-4 w-4 accent-[#c9f27a]" /></label><Field label="接口地址" value={settings.base_url} placeholder="http://127.0.0.1:48760/v1" onChange={(base_url) => setSettings({ ...settings, base_url })} /><div><Field label="模型名称" value={settings.model} placeholder="连接测试后选择或直接输入" onChange={(model) => setSettings({ ...settings, model })} />{models.length > 0 && <div className="mt-2 flex flex-wrap gap-1.5">{models.slice(0, 12).map((model) => <button type="button" key={model} onClick={() => setSettings({ ...settings, model })} className="rounded-md border border-white/[0.07] px-2 py-1 text-[9px] text-slate-500 hover:border-signal/20 hover:text-signal">{model}</button>)}</div>}</div><label className="block"><div className="mb-2 flex items-center justify-between text-[11px]"><span className="text-slate-500">API Key</span>{settings.has_api_key && <span className="flex items-center gap-1 text-[9px] text-signal"><Check size={10} /> 已保存</span>}</div><div className="flex h-11 items-center gap-2 rounded-xl border border-white/[0.08] bg-black/20 px-3"><KeyRound size={14} className="text-slate-600" /><input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder={settings.has_api_key ? '留空以继续使用已保存密钥' : '输入本地模型 API Key'} className="min-w-0 flex-1 bg-transparent text-xs text-white outline-none placeholder:text-slate-700" /></div></label><div className="grid grid-cols-2 gap-3"><Field label="超时（秒）" value={String(settings.timeout_seconds)} type="number" onChange={(value) => setSettings({ ...settings, timeout_seconds: Number(value) })} /><Field label="最大输出 Token" value={String(settings.max_tokens)} type="number" onChange={(value) => setSettings({ ...settings, max_tokens: Number(value) })} /></div>{message && <div className={`rounded-xl border px-3 py-2.5 text-xs ${message.includes('成功') || message.includes('保存') ? 'border-signal/15 bg-signal/[0.05] text-signal' : 'border-ember/15 bg-ember/[0.05] text-ember'}`}>{message}</div>}<div className="flex gap-2"><button type="button" onClick={() => void test()} disabled={busy !== null} className="filter-button h-11 flex-1 justify-center"><PlugZap size={15} />{busy === 'test' ? '测试中…' : '测试连接'}</button><button type="button" onClick={() => void save()} disabled={busy !== null} className="flex h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-signal text-xs font-semibold text-[#11170a] disabled:opacity-50">{busy === 'save' ? <LoaderCircle size={15} className="animate-spin" /> : <Save size={15} />}保存配置</button></div></div>}</div></div>
}

function Field({ label, value, placeholder, type = 'text', onChange }: { label: string; value: string; placeholder?: string; type?: string; onChange: (value: string) => void }) {
  return <label className="block"><span className="mb-2 block text-[11px] text-slate-500">{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="h-11 w-full rounded-xl border border-white/[0.08] bg-black/20 px-3 text-xs text-white outline-none transition placeholder:text-slate-700 focus:border-signal/25" /></label>
}
