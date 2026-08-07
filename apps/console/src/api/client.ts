import type {
  IntelligenceFilters,
  IntelligenceStatistics,
  Overview,
  RelevancePolicy,
  SyncRun,
  VulnerabilityPage,
  Vulnerability,
  SemanticAnalysis,
  SemanticJob,
  SemanticModelSettings,
  SemanticOverview,
  SemanticAssociation,
  SemanticCatalogItem,
  SemanticCategory,
  SemanticExploreKind,
  SemanticExplorePage,
  InterfaceStructureRecommendation,
  FirmwareCatalogOverview,
  FirmwareSource,
  FirmwareCandidatePage,
  FirmwareCandidateDetail,
  FirmwareCandidate,
} from '../types'

interface Envelope<T> {
  data: T
  request_id: string
}

interface ErrorEnvelope {
  error: string
  request_id?: string
}

let fallbackRequestSequence = 0

function createRequestId(): string {
  const randomUUID = globalThis.crypto?.randomUUID
  if (typeof randomUUID === 'function') {
    return randomUUID.call(globalThis.crypto)
  }

  fallbackRequestSequence += 1
  return [
    'req',
    Date.now().toString(36),
    fallbackRequestSequence.toString(36),
    Math.random().toString(36).slice(2, 10),
  ].join('-')
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': createRequestId(),
      ...init?.headers,
    },
  })
  const payload = (await response.json()) as Envelope<T> | ErrorEnvelope
  if (!response.ok || 'error' in payload) {
    throw new Error('error' in payload ? payload.error : `请求失败 (${response.status})`)
  }
  return payload.data
}

export const intelligenceApi = {
  overview: () => request<Overview>('/api/intelligence/overview'),
  statistics: () => request<IntelligenceStatistics>('/api/intelligence/statistics'),
  vulnerabilities: (filters: IntelligenceFilters, page = 1, signal?: AbortSignal) => {
    const params = new URLSearchParams({
      relevance: filters.relevance,
      page_size: '50',
      page: String(page),
    })
    if (filters.query) params.set('q', filters.query)
    if (filters.vendor) params.set('vendor', filters.vendor)
    if (filters.severity) params.set('severity', filters.severity)
    if (filters.kevOnly) params.set('kev', 'true')
    if (filters.exploitOnly) params.set('exploit', 'true')
    return request<VulnerabilityPage>(`/api/intelligence/vulnerabilities?${params}`, { signal })
  },
  vulnerability: (identifier: string, signal?: AbortSignal) =>
    request<Vulnerability>(`/api/intelligence/vulnerabilities/${encodeURIComponent(identifier)}`, { signal }),
  latestSync: () => request<SyncRun | null>('/api/intelligence/sync/latest'),
  sync: (days = 1) =>
    request<{ request_id: string; status: string }>('/api/intelligence/sync', {
      method: 'POST',
      body: JSON.stringify({ sources: ['nvd', 'cisa-kev'], days }),
    }),
  settings: () => request<RelevancePolicy>('/api/intelligence/settings'),
  updateSettings: (policy: Partial<RelevancePolicy>) =>
    request<{ policy: RelevancePolicy; reclassified_count: number }>(
      '/api/intelligence/settings',
      { method: 'PUT', body: JSON.stringify(policy) },
    ),
  semanticOverview: () => request<SemanticOverview>('/api/intelligence/semantic/overview'),
  semanticCategories: () => request<{ items: SemanticCategory[]; total: number }>(
    '/api/intelligence/semantic/categories',
  ),
  recommendInterfaceStructure: (value: string, page = 1, signal?: AbortSignal) => {
    const params = new URLSearchParams({ value, page: String(page), page_size: '20' })
    return request<InterfaceStructureRecommendation>(
      `/api/intelligence/semantic/interface-recommendation?${params}`, { signal },
    )
  },
  semanticExplore: (
    kind: SemanticExploreKind, page = 1, query = '', value = '', signal?: AbortSignal,
    subtype = '',
  ) => {
    const params = new URLSearchParams({ kind, page: String(page), page_size: '20' })
    if (query) params.set('q', query)
    if (value) params.set('value', value)
    if (subtype) params.set('subtype', subtype)
    return request<SemanticExplorePage<SemanticCatalogItem | SemanticAssociation>>(
      `/api/intelligence/semantic/explore?${params}`, { signal },
    )
  },
  semanticLatestJob: () => request<SemanticJob | null>('/api/intelligence/semantic/jobs/latest'),
  startSemanticJob: (force = false, useLlm = false) =>
    request<{ request_id: string; status: string }>('/api/intelligence/semantic/jobs', {
      method: 'POST', body: JSON.stringify({ force, use_llm: useLlm }),
    }),
  semanticAnalysis: (identifier: string) =>
    request<SemanticAnalysis | null>(`/api/intelligence/vulnerabilities/${encodeURIComponent(identifier)}/semantic-analysis`),
  analyzeVulnerability: (identifier: string, force = false) =>
    request<SemanticAnalysis>(`/api/intelligence/vulnerabilities/${encodeURIComponent(identifier)}/semantic-analysis`, {
      method: 'POST', body: JSON.stringify({ force }),
    }),
  semanticSettings: () => request<SemanticModelSettings>('/api/intelligence/semantic/settings'),
  updateSemanticSettings: (settings: Partial<SemanticModelSettings> & { api_key?: string; clear_api_key?: boolean }) =>
    request<SemanticModelSettings>('/api/intelligence/semantic/settings', {
      method: 'PUT', body: JSON.stringify(settings),
    }),
  testSemanticModel: (settings: { base_url?: string; api_key?: string; model?: string }) =>
    request<{ ok: boolean; models: string[] }>('/api/intelligence/semantic/settings/test', {
      method: 'POST', body: JSON.stringify(settings),
    }),
  firmwareOverview: () => request<FirmwareCatalogOverview>('/api/firmware/overview'),
  firmwareSources: () => request<{ items: FirmwareSource[] }>('/api/firmware/sources'),
  firmwareCandidates: (filters: {
    query?: string
    vendor?: string
    source?: string
    host?: string
    hasVulnerability?: boolean
    match?: string
  }, page = 1, signal?: AbortSignal) => {
    const params = new URLSearchParams({ page: String(page), page_size: '30' })
    if (filters.query) params.set('q', filters.query)
    if (filters.vendor) params.set('vendor', filters.vendor)
    if (filters.source) params.set('source', filters.source)
    if (filters.host) params.set('host', filters.host)
    if (filters.hasVulnerability) params.set('has_vulnerability', 'true')
    if (filters.match) params.set('match', filters.match)
    return request<FirmwareCandidatePage>(`/api/firmware/candidates?${params}`, { signal })
  },
  firmwareCandidate: (candidateId: string, signal?: AbortSignal) =>
    request<FirmwareCandidateDetail>(
      `/api/firmware/candidates/${encodeURIComponent(candidateId)}`, { signal },
    ),
  firmwareSamplesForVulnerability: (identifier: string, signal?: AbortSignal) =>
    request<{ identifier: string; items: FirmwareCandidate[]; total: number }>(
      `/api/firmware/vulnerabilities/${encodeURIComponent(identifier)}/samples`, { signal },
    ),
}
