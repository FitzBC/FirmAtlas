import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { intelligenceApi } from '../api/client'
import { SemanticExplorer } from './SemanticExplorer'

afterEach(() => vi.restoreAllMocks())

it('drills from an interface into associated vendors and firmware', async () => {
  vi.spyOn(intelligenceApi, 'semanticExplore')
    .mockResolvedValueOnce({
      items: [{
        value: '/goform/apply', category: 'form_handler', kind: 'http_route',
        method: 'POST', protocol: 'HTTP', component: 'Web Interface',
        occurrence_count: 2, vulnerability_count: 2, vendor_count: 2,
        vendors: ['D-Link', 'Tenda'], latest_at: '2025-01-01T00:00:00Z',
      }],
      total: 1, limit: 20, offset: 0, page: 1, pages: 1,
      has_previous: false, has_next: false,
    })
    .mockResolvedValueOnce({
      selection: { value: '/goform/apply', category: 'form_handler', method: 'POST', protocol: 'HTTP' },
      items: [{
        identifier: 'CVE-2025-0001', title: 'Router command injection', summary: 'summary',
        published_at: '2025-01-01T00:00:00Z', modified_at: '2025-01-02T00:00:00Z',
        vendor: 'D-Link', product: 'DIR-816 firmware', severity: 'CRITICAL', cvss_score: 9.8,
        cpes: ['cpe:2.3:o:dlink:dir-816_firmware:1.0:*:*:*:*:*:*:*'],
        matched_values: '/goform/apply', semantic_evidence: 'endpoint evidence',
      }],
      total: 1, limit: 20, offset: 0, page: 1, pages: 1,
      has_previous: false, has_next: false,
    } as never)
  vi.spyOn(intelligenceApi, 'vulnerability').mockResolvedValue({
    identifier: 'CVE-2025-0001', title: 'Router command injection',
    summary: 'Full firmware vulnerability narrative from the canonical record.',
    published_at: '2025-01-01T00:00:00Z', modified_at: '2025-01-02T00:00:00Z',
    vendor: 'D-Link', product: 'DIR-816 firmware', severity: 'CRITICAL', cvss_score: 9.8,
    cvss_vector: null, cvss_version: '3.1', impact_score: null, exploitability_score: null,
    attack_vector: 'NETWORK', attack_complexity: 'LOW', privileges_required: 'NONE',
    user_interaction: 'NONE', scope: 'UNCHANGED', cvss_metrics: [], aliases: [], cwes: ['CWE-78'],
    cpes: [], references: [], reference_details: [], exploit_references: [], has_exploit: false,
    cwe_details: [], affected_products: [], sources: ['NVD'], kev: false, kev_date_added: null,
    kev_due_date: null, ransomware_use: null, required_action: null, relevance_score: 90,
    relevance_level: 'strong', relevance_signals: [], policy_version: 'test', is_firmware_related: true,
    semantic_interface_count: 1, semantic_parameter_count: 1,
  })
  vi.spyOn(intelligenceApi, 'semanticAnalysis').mockResolvedValue(null)

  render(<SemanticExplorer mode="interface" />)

  fireEvent.click(await screen.findByRole('button', { name: /\/goform\/apply/ }))
  expect(await screen.findByText('DIR-816 firmware')).toBeInTheDocument()
  expect(screen.getByText('D-Link')).toBeInTheDocument()
  expect(screen.getByText('endpoint evidence')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /CVE-2025-0001.*Router command injection/i }))
  expect(await screen.findByText('Full firmware vulnerability narrative from the canonical record.')).toBeInTheDocument()
})

it('renders intelligent style categories as an explorable visual map', async () => {
  vi.spyOn(intelligenceApi, 'semanticCategories').mockResolvedValue({
    total: 1,
    items: [{
      key: 'cgi_gateway', label: 'CGI 网关', description: '传统 CGI 管理入口', tone: 'ember',
      interface_count: 308, vulnerability_count: 210, vendor_count: 12, firmware_count: 44,
      vendors: ['D-Link', 'Tenda'], latest_at: '2025-01-01T00:00:00Z',
      top_interfaces: [{ value: '/cgi-bin/apply.cgi', value_count: 30 }],
    }],
  })

  render(<SemanticExplorer mode="category" />)

  expect((await screen.findAllByText('CGI 网关')).length).toBeGreaterThan(0)
  expect(screen.getByText('210 个关联漏洞')).toBeInTheDocument()
  expect(screen.getByText('/cgi-bin/apply.cgi')).toBeInTheDocument()
})

it('filters vendor and firmware families by backend architecture style', async () => {
  vi.spyOn(intelligenceApi, 'semanticCategories').mockResolvedValue({
    total: 1,
    items: [{
      key: 'web_action', label: '动态页面动作', description: '动态控制器入口', tone: 'blue',
      interface_count: 3, vulnerability_count: 3, vendor_count: 2, firmware_count: 3,
      vendors: ['D-Link', 'Tenda'], latest_at: '2025-01-01T00:00:00Z',
      top_interfaces: [{ value: '/upgrade_filter.asp', value_count: 1 }],
    }],
  })
  const explore = vi.spyOn(intelligenceApi, 'semanticExplore').mockResolvedValue({
    selection: {
      key: 'web_action', label: '动态页面动作', description: '动态控制器入口',
      interface_count: 3, vulnerability_count: 3, vendor_count: 2, firmware_count: 3,
      scope_interface_count: 3, scope_vulnerability_count: 3, scope_vendor_count: 2, scope_model_count: 3,
      active_subtype: null,
      subtypes: [{ key: 'flat_page_controller', label: '扁平页面控制器', description: '根目录文件映射控制器', interface_count: 3, vulnerability_count: 3, vendor_count: 2, model_count: 3, examples: [{ value: '/upgrade_filter.asp', vulnerability_count: 1 }] }],
      top_vendors: [{ vendor: 'D-Link', vulnerability_count: 2, model_count: 2 }],
      top_models: [{ key: 'd-link dir-816 a2', label: 'D-Link DIR-816 A2 固件', vendor: 'D-Link', model: 'DIR-816 A2', version_summary: '1.10CNB04', source: 'description', alignment: 'aligned', vulnerability_count: 1 }],
    },
    items: [{
      value: '/upgrade_filter.asp', category: 'web_action', subtype: 'flat_page_controller', subtype_label: '扁平页面控制器',
      kind: 'http_route', method: 'POST', protocol: 'HTTP', occurrence_count: 1,
      vulnerability_count: 1, vendor_count: 1, vendors: ['D-Link'], latest_at: '2025-01-01T00:00:00Z',
    }],
    total: 1, limit: 20, offset: 0, page: 1, pages: 1, has_previous: false, has_next: false,
  } as never)

  render(<SemanticExplorer mode="category" />)
  fireEvent.click(await screen.findByRole('button', { name: /动态页面动作/ }))

  expect(await screen.findByText('D-Link DIR-816 A2 固件')).toBeInTheDocument()
  expect(screen.getAllByText('扁平页面控制器').length).toBeGreaterThan(0)
  expect(screen.getAllByText('/upgrade_filter.asp').length).toBeGreaterThan(0)
  fireEvent.click(screen.getAllByRole('button', { name: /扁平页面控制器/ })[0])
  await waitFor(() => expect(explore).toHaveBeenLastCalledWith('category', 1, '', 'web_action', expect.any(AbortSignal), 'flat_page_controller'))
  fireEvent.change(screen.getByPlaceholderText('搜索该类别下的接口…'), { target: { value: 'upgrade' } })
  await new Promise((resolve) => setTimeout(resolve, 260))
  expect(explore).toHaveBeenLastCalledWith('category', 1, 'upgrade', 'web_action', expect.any(AbortSignal), 'flat_page_controller')
})

it('keeps the catalog usable when an observation has no identified vendor', async () => {
  vi.spyOn(intelligenceApi, 'semanticExplore').mockResolvedValue({
    items: [{
      value: '/unknown/action', category: 'management_route', kind: 'http_route',
      occurrence_count: 1, vulnerability_count: 1, vendor_count: 0,
      vendors: null, latest_at: null,
    }],
    total: 1, limit: 20, offset: 0, page: 1, pages: 1,
    has_previous: false, has_next: false,
  } as never)

  render(<SemanticExplorer mode="interface" />)

  expect(await screen.findByText('/unknown/action')).toBeInTheDocument()
  expect(screen.getByText('0 家厂商')).toBeInTheDocument()
})
