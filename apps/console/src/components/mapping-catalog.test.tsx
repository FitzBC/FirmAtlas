import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { intelligenceApi } from '../api/client'
import type {
  MappingCandidate, MappingCandidateDetail, MappingCatalogSummary,
  MappingCorpusReport,
  MappingSnapshotDiff, PotentialHiddenInterfacePage,
  CommunicationGraphQueryResult, CommunicationGraphSummary,
  HistoricalGraphOverlayQueryResult,
  HistoricalCoverageLedgerQueryResult,
} from '../types'
import { MappingCatalogWorkspace } from './MappingCatalogWorkspace'

const catalog: MappingCatalogSummary = {
  catalog_id: 'discovery-catalog:abc', schema_version: 'firmatlas.mapping.discovery-catalog/v1alpha1',
  firmware_artifact_sha256: '1'.repeat(64), source_inventory_sha256: '2'.repeat(64),
  coverage_status: 'partial', source_inventory_coverage_status: 'partial',
  scheduler_termination: 'fixed_point',
  published_at: '2026-08-09T00:00:00Z', candidate_count: 1, parameter_count: 2,
  association_count: 0, open_obligation_count: 0,
}
const corpusReport: MappingCorpusReport = {
  schema_version: 'firmatlas.mapping.corpus-report/v1alpha2',
  report_id: `corpus-report:${'c'.repeat(64)}`,
  corpus_version: 'firmatlas-representative-corpus/m1.3', gate_status: 'passed',
  required_categories: ['form_handler', 'hnap_soap', 'cgi_gateway', 'script_backend', 'native_only'],
  categories: ['form_handler', 'hnap_soap', 'cgi_gateway', 'script_backend', 'native_only'].map((architecture_category) => ({
    architecture_category, status: 'verified', sample_count: 1,
    real_firmware_verified_count: 1, derived_firmware_verified_count: 0,
    contract_verified_count: 0, coverage_gap_count: architecture_category === 'script_backend' ? 1 : 0,
    acquisition_gap_count: 0, observed_capabilities: ['mentions_endpoint'],
    candidate_kinds: ['request_interface'], open_obligation_count: 0,
  })),
  samples: [{
    sample_id: 'dap3520-script-backend', architecture_category: 'script_backend',
    architecture_subtype: 'asp-command-backend', role: 'positive', evidence_tier: 'real_firmware',
    status: 'verified', catalog_id: 'catalog:dap3520',
    required_capabilities: ['reads_parameter', 'writes_configuration'],
    forbidden_capabilities: ['constructs_request'],
    observed_capabilities: ['reads_parameter', 'writes_configuration'],
    missing_capabilities: [], unexpected_capabilities: [], candidate_kinds: ['script_route'],
    candidate_count: 268, evidence_count: 276, open_obligation_count: 0,
    scope_candidate_ids: ['script-route:1'],
  }, {
    sample_id: 'x5000r-native-only', architecture_category: 'native_only',
    architecture_subtype: 'native-registration-no-frontend-reference', role: 'positive',
    evidence_tier: 'real_firmware', status: 'verified', catalog_id: 'catalog:x5000r',
    required_capabilities: ['binds_handler', 'mentions_endpoint'],
    forbidden_capabilities: ['constructs_request'],
    observed_capabilities: ['binds_handler', 'mentions_endpoint'],
    missing_capabilities: [], unexpected_capabilities: [], candidate_kinds: ['native_route_binding'],
    candidate_count: 10, evidence_count: 40, open_obligation_count: 0,
    scope_candidate_ids: ['native-binding:1'],
  }],
}
const candidate: MappingCandidate = {
  candidate_id: 'request:abc', candidate_kind: 'request_interface',
  canonical_identity: '/goform/SetOnlineDevName', claim_status: 'candidate',
  source_path: 'webroot/js/online.js', source_construct: 'jQuery.post',
  evidence_ids: ['ev:1'], attributes: [['method', 'POST']],
  parameter_count: 2, association_count: 0, open_obligation_count: 0,
}
const detail: MappingCandidateDetail = {
  catalog: {
    catalog_id: catalog.catalog_id,
    coverage_status: 'partial',
    source_inventory_coverage_status: 'partial',
    scheduler_termination: 'fixed_point',
  },
  candidate,
  parameters: [{ parameter_id: 'p:1', name: 'devName', namespace: 'form', literal_value: null, selector_values: [], is_operation_selector: false, source_construct: 'form_urlencoded' }],
  associations: [],
  related_candidates: [{
    ...candidate, candidate_id: 'native-binding:1', candidate_kind: 'native_route_binding',
    canonical_identity: 'SetOnlineDevName', claim_status: 'supported',
    source_path: 'bin/httpd', source_construct: 'elf.named-route-handler-pairs/v1:.routes',
  }, {
    ...candidate, candidate_id: 'ubus-binding:1', candidate_kind: 'ubus_backend_binding',
    canonical_identity: 'ubus://luci/getFeatures', claim_status: 'supported',
    source_path: 'usr/lib/rpcd/luci.so', source_construct: 'verified_native_registration',
    attributes: [['binding_status', 'verified_native_registration'], ['handler_identity', 'usr/lib/rpcd/luci.so@0x00001200']],
  }, {
    ...candidate, candidate_id: 'ubus-principal:1', candidate_kind: 'runtime_principal',
    canonical_identity: 'usr/libexec/rpcd/luci', claim_status: 'supported',
    source_path: 'usr/libexec/rpcd/luci', source_construct: 'rpcd_exec_plugin',
    attributes: [['principal_kind', 'rpcd_exec_plugin']],
  }, {
    ...candidate, candidate_id: 'ubus-grant:1', candidate_kind: 'ubus_access_grant',
    canonical_identity: 'ubus://luci/getFeatures', claim_status: 'supported',
    source_path: 'usr/share/rpcd/acl.d/luci-base.json', source_construct: 'rpcd_acl',
    attributes: [['access_mode', 'read'], ['policy_group', 'unauthenticated'], ['object_pattern', 'luci']],
  }],
  open_obligations: [{
    obligation_id: 'obligation:owner', target_ref: candidate.candidate_id, status: 'open',
    reason: 'No declared artifact scope statically binds this operation.',
    required_capability: 'resolve_ubus_runtime_owner', priority: 80,
    candidate_analyzers: ['rpcd-plugin-analyzer', 'ghidra-adapter'],
  }],
  evidence_atoms: [{ evidence_id: 'ev:1', predicate: 'constructs', object_value: candidate.canonical_identity, capability: 'constructs_request', source_span: { artifact_path: candidate.source_path, locator: 'text:1' } }],
  coverage: [{ scope: 'webroot/**/*.js', producer_kind: 'frontend', producer: 'frontend-request-producer', status: 'completed' }],
}
const urlIpcCandidate: MappingCandidate = {
  ...candidate,
  candidate_id: 'url-ipc:set', candidate_kind: 'native_configuration_url_ipc_flow',
  canonical_identity: 'SetUrlValue:opcode=30->cfm/url_mib/*', claim_status: 'supported',
  source_path: 'bin/cfmd', source_construct: 'arm32-cfm-url-ipc/v1',
  attributes: [
    ['operation', 'set'], ['channel_path', '/var/cfm_socket'], ['message_size', '2016'],
    ['request_opcode', '30'], ['response_opcodes', '[31]'], ['key_offset', '4'],
    ['value_offset', '516'], ['access_mode', 'write'],
  ], parameter_count: 0,
}
const urlIpcDetail: MappingCandidateDetail = {
  ...detail, candidate: urlIpcCandidate, parameters: [], related_candidates: [],
  open_obligations: [],
}
const cgiSelectorCandidate: MappingCandidate = {
  ...candidate,
  candidate_id: 'cgi-selector:upload-website', candidate_kind: 'native_cgi_selector',
  canonical_identity: '/cgi-bin/UploadWebsite', claim_status: 'supported',
  source_path: 'bin/httpd', source_construct: 'arm32-cgi-transport-selector-inventory/v1',
  attributes: [
    ['interface_path', '/cgi-bin/UploadWebsite'],
    ['interface_path_status', 'deterministic_derived'],
    ['selector', 'UploadWebsite'], ['comparison_width', '13'],
    ['handler_address', '0x0003e564'], ['method_status', 'unresolved'],
  ], parameter_count: 0,
}
const cgiSelectorDetail: MappingCandidateDetail = {
  ...detail, candidate: cgiSelectorCandidate, parameters: [], related_candidates: [],
  open_obligations: [{
    obligation_id: 'obligation:cgi-method', target_ref: cgiSelectorCandidate.candidate_id,
    status: 'open', reason: 'No selector-specific method guard was observed.',
    required_capability: 'binds_cgi_selector_http_method', priority: 80,
    candidate_analyzers: [],
  }],
}
const hiddenPage: PotentialHiddenInterfacePage = {
  items: [{
    interface_id: 'potential-hidden-interface:1', catalog_id: catalog.catalog_id,
    firmware_artifact_sha256: catalog.firmware_artifact_sha256,
    operation_token: 'UploadFirmwareFile', attribution_id: 'set-difference:1',
    registration_artifact_path: 'www/cgi-bin/cstecgi.cgi',
    binding_ids: ['native-route-binding:1'],
    handler_identities: ['www/cgi-bin/cstecgi.cgi@0x00419e8c'],
    frontend_coverage_scopes: ['www/**/*.{js,html}'],
    frontend_coverage_complete: true, runtime_reachability_verified: false,
    interpretation: 'Native registration has no observed frontend reference.',
    open_obligation: 'Test hidden clients, direct requests, and dead registrations.',
    evidence_ids: ['ev:native'],
  }],
  total: 1, limit: 200, offset: 0,
  summary: {
    firmware_count: 1, handler_count: 1,
    eligible_firmware_count: 1, coverage_gap_firmware_count: 2,
  },
  distributions: {
    firmware: [{
      firmware_artifact_sha256: catalog.firmware_artifact_sha256,
      catalog_id: catalog.catalog_id, count: 1,
    }],
    artifact: [{ path: 'www/cgi-bin/cstecgi.cgi', count: 1 }],
  },
}
const targetCatalog: MappingCatalogSummary = {
  ...catalog,
  catalog_id: 'discovery-catalog:def',
  firmware_artifact_sha256: '3'.repeat(64),
  coverage_status: 'completed', source_inventory_coverage_status: 'completed',
  published_at: '2026-08-10T00:00:00Z', candidate_count: 2,
}
const snapshotDiff: MappingSnapshotDiff = {
  schema_version: 'firmatlas.mapping.snapshot-diff/v1alpha1',
  comparison_id: 'mapping-snapshot-diff:1',
  base: { catalog_id: catalog.catalog_id, firmware_artifact_sha256: catalog.firmware_artifact_sha256 },
  target: { catalog_id: targetCatalog.catalog_id, firmware_artifact_sha256: targetCatalog.firmware_artifact_sha256 },
  comparison_status: 'coverage_confounded', same_firmware_family_verified: false,
  summary: {
    added_candidate_count: 1, removed_candidate_count: 0, changed_candidate_count: 1,
    added_parameter_count: 0, removed_parameter_count: 0, changed_parameter_count: 0,
    discovered_hidden_interface_count: 1, resolved_hidden_interface_count: 0,
    changed_hidden_interface_count: 0, coverage_change_count: 1, total_change_count: 4,
  },
  changes: [{
    change_id: 'mapping-snapshot-change:1', category: 'candidate',
    stable_identity: 'request_interface|/goform/SetOnlineDevName',
    display_identity: '/goform/SetOnlineDevName', change_kind: 'changed',
    confidence: 'coverage_confounded', changed_fields: ['attributes'],
    base: { attributes: [['method', 'POST']] },
    target: { attributes: [['method', 'PUT']] },
    interpretation: 'observed structural difference may be caused by analysis coverage drift',
  }],
  diagnostics: [{
    code: 'firmware_family_unverified',
    message: 'catalogs do not carry a verified release-family relation',
  }],
}

const graphSummary: CommunicationGraphSummary = {
  graph_id: 'communication-graph:ac9',
  schema_version: 'firmatlas.mapping.communication-architecture-graph/v1alpha1',
  source_catalog_id: catalog.catalog_id,
  firmware_artifact_sha256: catalog.firmware_artifact_sha256,
  source_catalog_coverage_status: 'completed', projection_status: 'completed',
  node_count: 5674, edge_count: 7212, published_at: '2026-08-11T00:00:00Z',
}

const graphResult = (nodes: CommunicationGraphQueryResult['nodes'], edges: CommunicationGraphQueryResult['edges'] = []): CommunicationGraphQueryResult => ({
  schema_version: 'firmatlas.mapping.communication-graph-query-result/v1alpha1',
  query_id: 'communication-graph-query:ac9',
  graph: {
    graph_id: graphSummary.graph_id, schema_version: graphSummary.schema_version,
    source_catalog_id: graphSummary.source_catalog_id,
    firmware_artifact_sha256: graphSummary.firmware_artifact_sha256,
    source_catalog_coverage_status: 'completed', projection_status: 'completed',
  },
  query: {
    text: '', preset_id: 'interface_structure', node_kinds: [], edge_kinds: [],
    statuses: [], evidence_id: '', focus_node_ids: [], focus_canonical_identities: [],
    max_hops: 3, max_nodes: 160, max_edges: 320,
  },
  query_status: 'completed', nodes, edges,
  total_node_count: nodes.length, total_edge_count: edges.length,
  selected_node_count: nodes.length, selected_edge_count: edges.length,
  evidence_atoms: [{
    evidence_id: 'evidence:dlna', subject_ref: 'interface:set-dlna',
    predicate: 'constructs_request', object_value: 'goform/SetDlnaCfg',
    capability: 'constructs_request', confidence: 0.9,
    observation_kind: 'direct_static', producer: 'frontend-request-producer',
    producer_version: '0.4.0', source_span: {
      artifact_path: 'webroot_ro/js/dlna.js', artifact_sha256: 'a'.repeat(64),
      locator: 'text_utf8:lines=22:1-22:20', span_kind: 'text_utf8',
      start_byte: 10, end_byte: 30, start_line: 22, end_line: 22,
    },
  }],
  facets: { node_kinds: { interface: 1 }, edge_kinds: {}, statuses: { supported: 1 } },
  coverage: [{
    scope: 'auto:frontend', producer_kind: 'frontend', producer: 'frontend-request-producer',
    producer_version: '0.4.0', status: 'completed', required: true,
    processed_result_count: 1, diagnostic: '',
  }],
  view_presets: [
    { preset_id: 'interface_structure', title: 'Interface structure', node_kinds: ['interface', 'parameter', 'obligation'], edge_kinds: ['accepts_parameter', 'requires_evidence'], description: 'Interface ownership and evidence.' },
    { preset_id: 'parameter_state', title: 'Parameter state', node_kinds: ['interface', 'parameter'], edge_kinds: ['accepts_parameter'], description: 'Parameters and state clues.' },
    { preset_id: 'communication_components', title: 'Communication components', node_kinds: ['interface', 'runtime_principal'], edge_kinds: ['executed_by'], description: 'Runtime communication shape.' },
    { preset_id: 'completeness', title: 'Completeness', node_kinds: ['interface', 'obligation'], edge_kinds: ['requires_evidence'], description: 'Coverage and unresolved obligations.' },
  ], diagnostics: [],
})

const interfaceNode = {
  node_id: 'interface:set-dlna', node_kind: 'interface', label: 'goform/SetDlnaCfg',
  status: 'supported', source_path: 'webroot_ro/js/dlna.js',
  evidence_ids: ['evidence:dlna'], attributes: [['canonical_identity', 'goform/SetDlnaCfg']] as Array<[string, string]>,
}
const cgiDispatchNode = {
  node_id: 'native-cgi-selector:upload-website', node_kind: 'dispatch',
  label: '/cgi-bin/UploadWebsite', status: 'supported', source_path: 'bin/httpd',
  evidence_ids: ['evidence:dlna'],
  attributes: [['handler_identity', 'bin/httpd@0x0003e564']] as Array<[string, string]>,
}
const parameterNode = {
  node_id: 'parameter:dlna-en', node_kind: 'parameter', label: 'dlnaEn',
  status: 'observed', source_path: 'webroot_ro/js/dlna.js',
  evidence_ids: ['evidence:dlna'], attributes: [['namespace', 'form']] as Array<[string, string]>,
}
const obligationNode = {
  node_id: 'obligation:dlna-owner', node_kind: 'obligation', label: 'Resolve DLNA handler owner',
  status: 'open', source_path: 'bin/httpd', evidence_ids: [],
  attributes: [['required_capability', 'binds_handler']] as Array<[string, string]>,
}
const configurationFlowNode = {
  node_id: 'native-configuration-blob-flow:1', node_kind: 'communication_relation',
  label: 'UploadValue:opcode=14->configuration_partition[0]', status: 'supported',
  source_path: 'bin/cfmd', evidence_ids: ['evidence:dlna'],
  attributes: [['request_opcode', '14']] as Array<[string, string]>,
}
const configurationStateNode = {
  node_id: 'configuration-state:1', node_kind: 'state',
  label: 'configuration_partition[0]', status: 'supported', source_path: '',
  evidence_ids: ['evidence:dlna'],
  attributes: [['write_granularity', 'whole_configuration_image']] as Array<[string, string]>,
}

const historicalOverlay: HistoricalGraphOverlayQueryResult = {
  schema_version: 'firmatlas.mapping.historical-graph-overlay-query-result/v1alpha1',
  query_id: 'historical-graph-overlay-query:ac9',
  overlay: {
    schema_version: 'firmatlas.mapping.historical-graph-overlay/v1alpha1',
    overlay_id: 'historical-graph-overlay:ac9', graph_id: graphSummary.graph_id,
    catalog_id: catalog.catalog_id, expectation_diff_id: 'historical-expectation-diff:ac9',
    route_binding_report_id: 'historical-route-binding:ac9',
    claim_boundary: 'Historical vulnerability claims are contextual expectations only; graph links do not assert vulnerability presence.',
    summary: { status: { observed: 1 }, applicability: { out_of_scope: 1 } },
    vulnerability_audit: {
      audit_id: 'historical-vulnerability-audit:ac9', total_vulnerability_count: 71,
      category_counts: { compared_interface: 13, not_analyzed: 46 },
      exact_artifact_expectation_count: 2, exact_artifact_observed_count: 2,
    },
  },
  query: { text: '', statuses: [], applicabilities: [], gap_reasons: [], route_binding_statuses: [] },
  entries: [{
    expectation_id: 'historical-expectation:iptv', vulnerability_identifier: 'CVE-2025-5836',
    interface_value: '/goform/SetDlnaCfg', method: 'POST', handler_value: 'formSetIptv',
    expected_parameters: ['list'], source_ref: 'semantic-analysis:CVE-2025-5836',
    applicability: 'out_of_scope', claimed_versions: ['V15.03.06.42_multi'],
    applicability_basis: 'Different AC9 firmware lineage.', status: 'observed', gap_reason: 'none',
    gap_explanation: 'The expected interface, method, and parameters were observed in the evidence-backed catalog.',
    observed_methods: ['POST'], observed_parameters: ['list'], missing_parameters: [],
    catalog_candidate_ids: [interfaceNode.node_id], catalog_evidence_ids: ['evidence:dlna'],
    route_binding_status: 'verified_expected_handler', observed_handlers: ['formSetIptv'],
    graph_node_ids: [interfaceNode.node_id, parameterNode.node_id], graph_edge_ids: ['edge:parameter'],
    graph_link_bases: ['catalog_candidate_id', 'parameter_owner_edge'],
    unmapped_catalog_reference_ids: [], unmapped_catalog_evidence_ids: [],
  }],
  total_entry_count: 1, selected_entry_count: 1,
  facets: { status: { observed: 1 }, applicability: { out_of_scope: 1 }, gap_reason: { none: 1 }, route_binding_status: { verified_expected_handler: 1 } },
  diagnostics: [],
}

const historicalCoverage: HistoricalCoverageLedgerQueryResult = {
  schema_version: 'firmatlas.mapping.historical-coverage-ledger-query-result/v1alpha1',
  query_id: 'historical-coverage-ledger-query:ac9',
  ledger: {
    schema_version: 'firmatlas.mapping.historical-coverage-ledger/v1alpha1',
    ledger_id: 'historical-coverage-ledger:ac9', graph_id: graphSummary.graph_id,
    catalog_id: catalog.catalog_id, overlay_id: 'historical-graph-overlay:ac9',
    queue_id: 'historical-coverage-queue:ac9', audit_id: 'historical-vulnerability-audit:ac9',
    total_vulnerability_count: 71,
    claim_boundary: 'Historical coverage states describe evidence availability and structural observation only; they do not assert vulnerability presence, reachability, or exploitability.',
    summary: { status: { observed: 9, partial: 2, not_assessable: 60 } },
  },
  query: { text: '', statuses: [], audit_categories: [], evidence_states: [] },
  entries: [{
    vulnerability_identifier: 'CVE-2025-5836', audit_category: 'compared_interface',
    status: 'observed', reason_codes: ['none'], reason_explanations: ['Observed.'],
    action: 'none', evidence_state: 'structured', applicabilities: ['out_of_scope'],
    claimed_versions: ['V15.03.06.42_multi'], applicability_bases: ['Different AC9 firmware lineage.'],
    interface_values: ['/goform/SetDlnaCfg'], methods: ['POST'], handler_values: ['formSetIptv'],
    expected_parameters: ['list'], observed_parameters: ['list'], missing_parameters: [],
    configuration_keys: [], source_refs: ['semantic-analysis:CVE-2025-5836'],
    catalog_candidate_ids: [interfaceNode.node_id], catalog_evidence_ids: ['evidence:dlna'],
    graph_node_ids: [interfaceNode.node_id, parameterNode.node_id], graph_edge_ids: ['edge:parameter'],
  }, {
    vulnerability_identifier: 'CVE-2026-2191', audit_category: 'parameter_only',
    status: 'partial', reason_codes: ['configuration_key_misclassified_as_request_parameter', 'interface_observation_missing'],
    reason_explanations: [], action: 'repair_parameter_extraction', evidence_state: 'source_partial',
    applicabilities: [], claimed_versions: [], applicability_bases: [], interface_values: [], methods: [],
    handler_values: ['formGetDdosDefenceList'], expected_parameters: [], observed_parameters: ['security.ddos.map'],
    missing_parameters: [], configuration_keys: ['security.ddos.map'], source_refs: ['primary:tenda3'],
    catalog_candidate_ids: ['native-route:get-ddos'], catalog_evidence_ids: [], graph_node_ids: [], graph_edge_ids: [],
  }],
  total_entry_count: 71, selected_entry_count: 71,
  facets: { status: { observed: 9, partial: 2, not_assessable: 60 }, audit_category: { compared_interface: 14, parameter_only: 2, not_analyzed: 46, no_structured_communication: 9 }, evidence_state: { structured: 14, source_partial: 2, semantic_analysis_missing: 46, needs_primary_source: 9 } },
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

it('explains the scope-aware representative corpus gate without overstating generalization', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [candidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCorpusReport').mockResolvedValue(corpusReport)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '语料门禁' }))

  expect(await screen.findByText('五类通信架构门禁通过')).toBeInTheDocument()
  expect(screen.getByText('表单处理链')).toBeInTheDocument()
  expect(screen.getByText('HNAP / SOAP')).toBeInTheDocument()
  expect(screen.getByText('共享 CGI 网关')).toBeInTheDocument()
  expect(screen.getAllByText('已验证').length).toBeGreaterThanOrEqual(5)
  expect(screen.getByText('dap3520-script-backend')).toBeInTheDocument()
  expect(screen.getByText('268 候选 · 276 证据')).toBeInTheDocument()
  expect(screen.getByText('x5000r-native-only')).toBeInTheDocument()
  expect(screen.getByText('10 候选 · 40 证据')).toBeInTheDocument()
  expect(screen.getByText(/不等于所有厂商与子类型均已泛化验证/)).toBeInTheDocument()
})

it('uploads one firmware artifact and exposes its published mapping job', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [], total: 0, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [], total: 0, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingJobs').mockResolvedValue({
    enabled: true, max_upload_bytes: 64 * 1024 * 1024, items: [],
  })
  vi.spyOn(intelligenceApi, 'submitFirmwareMappingJob').mockResolvedValue({
    schema_version: 'firmatlas.mapping.job/v1alpha1',
    job_id: `firmware-mapping-job:${'a'.repeat(64)}`,
    original_filename: 'ac9.trx', firmware_artifact_sha256: 'b'.repeat(64),
    artifact_size: 12, runner_id: 'container-binwalk:test', status: 'completed',
    submitted_at: '2026-08-18T00:00:00Z', started_at: '2026-08-18T00:00:01Z',
    finished_at: '2026-08-18T00:00:02Z', artifact_analysis_id: 'analysis:ac9',
    catalog_id: 'catalog:ac9', graph_id: 'graph:ac9', error_code: null,
  })
  vi.spyOn(intelligenceApi, 'mappingReasoning').mockResolvedValue({
    enabled: true, adapter_id: 'minimax-reasoner:test', latest: null,
  })
  vi.spyOn(intelligenceApi, 'submitMappingReasoning').mockResolvedValue({
    schema_version: 'firmatlas.mapping.reasoning-run/v1alpha1',
    run_id: `mapping-reasoning-run:${'c'.repeat(64)}`,
    catalog_id: 'catalog:ac9', firmware_artifact_sha256: 'b'.repeat(64),
    adapter_id: 'minimax-reasoner:test', status: 'completed',
    submitted_at: '2026-08-18T00:00:03Z', attempt: 1, started_at: '2026-08-18T00:00:03Z',
    finished_at: '2026-08-18T00:00:04Z', rejected_proposal_count: 0,
    prompt_tokens: 120, completion_tokens: 40, error_code: null, diagnostics: [],
    proposals: [{
      proposal_id: `mapping-reasoning-proposal:${'d'.repeat(64)}`,
      kind: 'analysis_step', target_ref: 'candidate:ac9',
      summary: '追踪未决接口的注册调用点', rationale: '当前只存在前端请求证据。',
      cited_evidence_ids: ['evidence:ac9'],
      required_corroboration: '需要确定性 registrar call-site 证据',
      confidence: 0.82, status: 'model_suggested',
    }],
  })

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '上传分析' }))
  const file = new File([new Uint8Array(12)], 'ac9.trx', { type: 'application/octet-stream' })
  fireEvent.change(await screen.findByLabelText('选择固件制品'), {
    target: { files: [file] },
  })
  fireEvent.click(screen.getByRole('button', { name: '开始独立分析' }))

  expect(await screen.findByText('分析已完成')).toBeInTheDocument()
  expect(screen.getByText('ac9.trx')).toBeInTheDocument()
  expect(screen.getByText(/bbbbbbbbbbbbbbbb/)).toBeInTheDocument()
  expect(screen.getByText('graph:ac9')).toBeInTheDocument()
  fireEvent.click(await screen.findByRole('button', { name: '使用 MiniMax 补充分析线索' }))
  expect(await screen.findByText('追踪未决接口的注册调用点')).toBeInTheDocument()
  expect(screen.getByText('需要确定性 registrar call-site 证据')).toBeInTheDocument()
  expect(screen.getByText('模型建议不是已验证事实')).toBeInTheDocument()
})

it('navigates catalog, candidate and evidence levels without overlay drawers', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  const query = vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [candidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidate').mockResolvedValue(detail)

  render(<MappingCatalogWorkspace />)

  expect(await screen.findByText('/goform/SetOnlineDevName')).toBeInTheDocument()
  expect(screen.getAllByText('Inventory partial').length).toBeGreaterThan(0)
  fireEvent.click(screen.getByRole('button', { name: '请求接口' }))
  await waitFor(() => expect(query).toHaveBeenLastCalledWith(
    catalog.catalog_id, expect.objectContaining({ kind: 'request_interface' }), expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: '集合差异' }))
  await waitFor(() => expect(query).toHaveBeenLastCalledWith(
    catalog.catalog_id, expect.objectContaining({ kind: 'set_difference_attribution' }), expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: /查看候选/ }))
  expect(await screen.findByText('devName')).toBeInTheDocument()
  expect(screen.getByText('架构与分析属性')).toBeInTheDocument()
  expect(screen.getByText('method')).toBeInTheDocument()
  expect(screen.getByText('POST')).toBeInTheDocument()
  expect(screen.getByText('constructs_request')).toBeInTheDocument()
  expect(screen.getByText('后端执行与访问链')).toBeInTheDocument()
  expect(screen.getByText('SetOnlineDevName')).toBeInTheDocument()
  expect(screen.getByText('rpcd_exec_plugin')).toBeInTheDocument()
  expect(screen.getByText(/handler usr\/lib\/rpcd\/luci\.so@0x00001200/)).toBeInTheDocument()
  expect(screen.getByText('read · unauthenticated')).toBeInTheDocument()
  expect(screen.getByText('未决分析义务')).toBeInTheDocument()
  expect(screen.getByText('resolve_ubus_runtime_owner')).toBeInTheDocument()
})

it('renders URL IPC framing as a first-class communication detail', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [urlIpcCandidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidate').mockResolvedValue(urlIpcDetail)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: `查看候选 ${urlIpcCandidate.canonical_identity}` }))

  expect(await screen.findByText('URL 配置 IPC')).toBeInTheDocument()
  expect(screen.getByText('/var/cfm_socket · 2016 bytes · opcode@0 · key/path@4 · value@516')).toBeInTheDocument()
  expect(screen.getByText('set · request 30 · response [31] · write_state')).toBeInTheDocument()
})

it('explains deterministic CGI path composition without inventing a method', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  const query = vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [cgiSelectorCandidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidate').mockResolvedValue(cgiSelectorDetail)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: 'CGI 组合路由' }))
  await waitFor(() => expect(query).toHaveBeenLastCalledWith(
    catalog.catalog_id, expect.objectContaining({ kind: 'native_cgi_selector' }), expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: `查看候选 ${cgiSelectorCandidate.canonical_identity}` }))

  expect(await screen.findByText('CGI 组合式路由')).toBeInTheDocument()
  expect(screen.getAllByText('/cgi-bin/UploadWebsite').length).toBeGreaterThan(0)
  expect(screen.getByText(/不是完整 URL 字面量/)).toBeInTheDocument()
  expect(screen.getByText(/不会根据上传 body 猜测 POST/)).toBeInTheDocument()
  expect(screen.getByText('binds_cgi_selector_http_method')).toBeInTheDocument()
})

it('shows potential hidden interfaces as a coverage-gated cross-firmware view', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [catalog], total: 1, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  const hidden = vi.spyOn(intelligenceApi, 'potentialHiddenInterfaces')
    .mockResolvedValue(hiddenPage)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '潜在隐藏接口' }))

  expect(await screen.findByText('UploadFirmwareFile')).toBeInTheDocument()
  expect(screen.getByText('覆盖合格固件')).toBeInTheDocument()
  expect(screen.getByText('固件信号分布')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看潜在隐藏接口/ }))
  expect(screen.getByText('不是后门结论')).toBeInTheDocument()
  expect(screen.getByText('www/cgi-bin/cstecgi.cgi@0x00419e8c')).toBeInTheDocument()
  expect(hidden).toHaveBeenCalled()
})

it('compares two mapping snapshots without hiding coverage confounding', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [targetCatalog, catalog], total: 2, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  const compare = vi.spyOn(intelligenceApi, 'compareMappingCatalogs')
    .mockResolvedValue(snapshotDiff)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '版本对比' }))

  expect(await screen.findByText('覆盖不可直接比较')).toBeInTheDocument()
  expect(screen.getByText('新增结构')).toBeInTheDocument()
  expect(screen.getByText('潜在隐藏新增')).toBeInTheDocument()
  expect(screen.getByRole('textbox', { name: '搜索版本差异' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '接口 / 候选' })).toBeInTheDocument()
  expect(screen.getByText('/goform/SetOnlineDevName')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看版本差异/ }))
  expect(screen.getAllByText('attributes').length).toBeGreaterThan(0)
  expect(screen.getByText(/不能断言同型号版本谱系/)).toBeInTheDocument()
  fireEvent.change(screen.getByRole('textbox', { name: '搜索版本差异' }), {
    target: { value: 'ubus://' },
  })
  expect(screen.getByText('当前筛选范围没有观察到结构差异')).toBeInTheDocument()
  expect(compare).toHaveBeenCalledWith(
    catalog.catalog_id, targetCatalog.catalog_id, expect.any(AbortSignal),
  )
})

it('explores a persisted communication graph from interface to parameter and evidence', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [catalog], total: 1, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingGraphs').mockResolvedValue({
    items: [graphSummary], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingHistoricalOverlay').mockResolvedValue(historicalOverlay)
  const queryGraph = vi.spyOn(intelligenceApi, 'mappingGraph').mockImplementation(
    (_graphId, options) => Promise.resolve(options?.nodeKinds?.includes('interface')
      ? graphResult([interfaceNode])
      : graphResult([interfaceNode, parameterNode, obligationNode], [
        { edge_id: 'edge:parameter', edge_kind: 'accepts_parameter', source_ref: interfaceNode.node_id, target_ref: parameterNode.node_id, status: 'supported', origin_ref: parameterNode.node_id, evidence_ids: ['evidence:dlna'], attributes: [] },
        { edge_id: 'edge:obligation', edge_kind: 'requires_evidence', source_ref: interfaceNode.node_id, target_ref: obligationNode.node_id, status: 'open', origin_ref: obligationNode.node_id, evidence_ids: [], attributes: [] },
      ])),
  )

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '架构图谱' }))

  expect(await screen.findByText('goform/SetDlnaCfg')).toBeInTheDocument()
  expect(queryGraph).toHaveBeenCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({ nodeKinds: ['interface', 'dispatch', 'state'] }),
    expect.any(AbortSignal),
  )
  expect(screen.getByText('5,674')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /聚焦接口 goform\/SetDlnaCfg/ }))
  expect(await screen.findByText('dlnaEn')).toBeInTheDocument()
  expect(screen.getByText('Resolve DLNA handler owner')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看图节点 dlnaEn/ }))
  expect(screen.getByText('constructs_request')).toBeInTheDocument()
  expect(screen.getAllByText(/dlna\.js/).length).toBeGreaterThan(0)
  fireEvent.click(screen.getByRole('button', { name: '参数与状态' }))
  await waitFor(() => expect(queryGraph).toHaveBeenLastCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({ preset: 'parameter_state', focusNodeIds: [interfaceNode.node_id] }),
    expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: '通信组件' }))
  await waitFor(() => expect(queryGraph).toHaveBeenLastCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({
      preset: 'communication_components',
      focusNodeIds: [interfaceNode.node_id],
      maxHops: 8,
      maxNodes: 240,
      maxEdges: 480,
    }),
    expect.any(AbortSignal),
  ))
})

it('keeps derived CGI dispatch routes searchable in the graph structure index', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [candidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingGraphs').mockResolvedValue({ items: [graphSummary], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingHistoricalOverlay').mockResolvedValue(historicalOverlay)
  const queryGraph = vi.spyOn(intelligenceApi, 'mappingGraph').mockImplementation(
    (_graphId, options) => Promise.resolve(options?.query === 'UploadWebsite'
      ? graphResult([cgiDispatchNode]) : graphResult([interfaceNode])),
  )

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '架构图谱' }))
  fireEvent.change(screen.getByRole('textbox', { name: '搜索通信接口或状态' }), {
    target: { value: 'UploadWebsite' },
  })

  expect(await screen.findByRole('button', { name: '聚焦分发 /cgi-bin/UploadWebsite' })).toBeInTheDocument()
  expect(queryGraph).toHaveBeenLastCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({ query: 'UploadWebsite', nodeKinds: ['interface', 'dispatch', 'state'] }),
    expect.any(AbortSignal),
  )
})

it('compacts sparse semantic ranks so a focused state flow stays inside the graph viewport', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [catalog], total: 1, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingGraphs').mockResolvedValue({
    items: [graphSummary], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingHistoricalOverlay').mockResolvedValue(historicalOverlay)
  vi.spyOn(intelligenceApi, 'mappingGraph').mockImplementation(
    (_graphId, options) => Promise.resolve(options?.nodeKinds?.includes('state')
      ? graphResult([configurationStateNode])
      : graphResult([configurationFlowNode, configurationStateNode], [{
        edge_id: 'edge:writes-state', edge_kind: 'writes_state',
        source_ref: configurationFlowNode.node_id, target_ref: configurationStateNode.node_id,
        status: 'supported', origin_ref: configurationFlowNode.node_id,
        evidence_ids: ['evidence:dlna'], attributes: [],
      }])),
  )

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '架构图谱' }))
  fireEvent.click(await screen.findByRole('button', {
    name: '聚焦状态 configuration_partition[0]',
  }))

  await waitFor(() => expect(intelligenceApi.mappingGraph).toHaveBeenLastCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({
      focusNodeIds: [configurationStateNode.node_id],
      maxHops: 1,
      maxNodes: 32,
      maxEdges: 64,
    }),
    expect.any(AbortSignal),
  ))

  const flow = await screen.findByRole('button', {
    name: '查看图节点 UploadValue:opcode=14->configuration_partition[0]',
  })
  const state = screen.getByRole('button', {
    name: '查看图节点 configuration_partition[0]',
  })
  expect(Math.abs(parseInt(flow.style.left) - parseInt(state.style.left))).toBe(200)
})

it('overlays AC9 historical expectations without turning cross-version presence into a vulnerability fact', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [catalog], total: 1, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingGraphs').mockResolvedValue({
    items: [graphSummary], total: 1, limit: 100, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingHistoricalOverlay').mockResolvedValue(historicalOverlay)
  vi.spyOn(intelligenceApi, 'mappingHistoricalCoverage').mockResolvedValue(historicalCoverage)
  const queryGraph = vi.spyOn(intelligenceApi, 'mappingGraph').mockImplementation(
    (_graphId, options) => Promise.resolve(options?.nodeKinds?.includes('interface')
      ? graphResult([interfaceNode])
      : graphResult([interfaceNode, parameterNode], [{
        edge_id: 'edge:parameter', edge_kind: 'accepts_parameter',
        source_ref: interfaceNode.node_id, target_ref: parameterNode.node_id,
        status: 'supported', origin_ref: parameterNode.node_id,
        evidence_ids: ['evidence:dlna'], attributes: [],
      }])),
  )

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '架构图谱' }))
  fireEvent.click(await screen.findByRole('button', { name: '历史漏洞对照' }))

  expect(await screen.findByText('CVE-2025-5836')).toBeInTheDocument()
  expect(screen.getByText('71')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看历史漏洞 CVE-2025-5836/ }))
  expect(await screen.findByText('Different AC9 firmware lineage.')).toBeInTheDocument()
  expect(screen.getByText('跨版本结构存在，不代表当前固件存在该漏洞')).toBeInTheDocument()
  expect(screen.getByText('formSetIptv')).toBeInTheDocument()
  await waitFor(() => expect(queryGraph).toHaveBeenLastCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({ focusNodeIds: [interfaceNode.node_id, parameterNode.node_id] }),
    expect.any(AbortSignal),
  ))
})

it('shows all AC9 vulnerabilities and explains parameter-only gaps without graph invention', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [candidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingGraphs').mockResolvedValue({ items: [graphSummary], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingHistoricalOverlay').mockResolvedValue(historicalOverlay)
  vi.spyOn(intelligenceApi, 'mappingHistoricalCoverage').mockResolvedValue(historicalCoverage)
  const queryGraph = vi.spyOn(intelligenceApi, 'mappingGraph').mockImplementation(
    (_graphId, options) => Promise.resolve(options?.nodeKinds?.includes('interface')
      ? graphResult([interfaceNode]) : graphResult([])),
  )

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '架构图谱' }))
  fireEvent.click(await screen.findByRole('button', { name: '历史漏洞对照' }))

  expect(await screen.findByText('71 条漏洞均已进入覆盖账本')).toBeInTheDocument()
  fireEvent.change(screen.getByRole('textbox', { name: '搜索历史漏洞' }), {
    target: { value: 'CVE-2026-2191' },
  })
  fireEvent.click(await screen.findByRole('button', { name: '查看历史漏洞 CVE-2026-2191' }))
  expect(screen.getByText('security.ddos.map')).toBeInTheDocument()
  expect(screen.getByText('配置键，不是已证明的 HTTP 参数')).toBeInTheDocument()
  expect(screen.getByText('repair_parameter_extraction')).toBeInTheDocument()
  expect(screen.getByText('该历史记录没有可用于图聚焦的 Catalog 证据')).toBeInTheDocument()
  expect(queryGraph).not.toHaveBeenCalledWith(
    graphSummary.graph_id,
    expect.objectContaining({ focusNodeIds: ['native-route:get-ddos'] }),
    expect.any(AbortSignal),
  )
})
