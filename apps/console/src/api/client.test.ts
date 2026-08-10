import { afterEach, describe, expect, it, vi } from 'vitest'

import { intelligenceApi } from './client'

describe('intelligence API client', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends requests when randomUUID is unavailable in an insecure context', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(
      JSON.stringify({ data: null, request_id: 'server-request-id' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )))
    vi.stubGlobal('crypto', {})
    vi.stubGlobal('fetch', fetchMock)

    await expect(intelligenceApi.latestSync()).resolves.toBeNull()
    await expect(intelligenceApi.latestSync()).resolves.toBeNull()

    const requestIds = fetchMock.mock.calls.map(([, init]) => (
      new Headers(init.headers).get('X-Request-ID')
    ))
    expect(requestIds[0]).toMatch(/^req-[a-z0-9-]+$/)
    expect(requestIds[1]).not.toBe(requestIds[0])
  })

  it('encodes graph focus and kind filters without collapsing repeated values', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ data: { nodes: [], edges: [] }, request_id: 'graph-request' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ))
    vi.stubGlobal('fetch', fetchMock)

    await intelligenceApi.mappingGraph('communication-graph:abc', {
      preset: 'interface_structure',
      query: 'dlna',
      nodeKinds: ['interface', 'parameter'],
      focusNodeIds: ['node:one', 'node:two'],
      maxHops: 3,
      maxNodes: 120,
      maxEdges: 240,
    })

    const url = new URL(fetchMock.mock.calls[0][0], 'http://firmatlas.local')
    expect(url.pathname).toBe('/api/mappings/graphs/communication-graph%3Aabc')
    expect(url.searchParams.get('preset')).toBe('interface_structure')
    expect(url.searchParams.get('q')).toBe('dlna')
    expect(url.searchParams.getAll('node_kind')).toEqual(['interface', 'parameter'])
    expect(url.searchParams.getAll('focus_node')).toEqual(['node:one', 'node:two'])
    expect(url.searchParams.get('max_hops')).toBe('3')
  })
})
