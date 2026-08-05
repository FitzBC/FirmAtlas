import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { intelligenceApi } from '../api/client'
import { SemanticAnalysisWorkspace } from './SemanticAnalysisWorkspace'

afterEach(() => vi.restoreAllMocks())

it('shows real semantic coverage and starts an incremental cached batch', async () => {
  vi.spyOn(intelligenceApi, 'semanticOverview').mockResolvedValue({
    total: 19218, analyzed: 19218, pending: 0, interfaces: 2048,
    parameters: 2173, prompt_tokens: 0, completion_tokens: 0,
    top_interfaces: [{ label: '/cgi-bin/cstecgi.cgi', value: 308 }],
    top_parameters: [{ label: 'page', value: 117 }],
  })
  vi.spyOn(intelligenceApi, 'semanticLatestJob').mockResolvedValue({
    job_id: 'job', status: 'succeeded', strategy: 'rules', force: 0,
    total_count: 19218, processed_count: 19218, analyzed_count: 0,
    cached_count: 19218, failed_count: 0, interfaces_count: 0,
    parameters_count: 0, started_at: '2026-08-05T00:00:00Z',
    finished_at: '2026-08-05T00:01:00Z', error: null,
  })
  vi.spyOn(intelligenceApi, 'semanticSettings').mockResolvedValue({
    enabled: false, base_url: 'http://127.0.0.1:48760/v1', model: '',
    timeout_seconds: 45, temperature: 0, max_tokens: 1400,
    has_api_key: false, active: false,
  })
  const start = vi.spyOn(intelligenceApi, 'startSemanticJob').mockResolvedValue({
    request_id: 'request', status: 'accepted',
  })

  render(<SemanticAnalysisWorkspace onConfigureModel={vi.fn()} />)

  expect(await screen.findByText('100.0% 已建立分析记录')).toBeInTheDocument()
  expect(screen.getByText('/cgi-bin/cstecgi.cgi')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '检查新增记录' }))
  expect(start).toHaveBeenCalledWith(false)
})
