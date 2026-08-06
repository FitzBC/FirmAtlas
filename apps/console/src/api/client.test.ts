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
})
