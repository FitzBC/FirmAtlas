export type RelevanceLevel = 'strong' | 'likely' | 'review' | 'unrelated'

export interface RelevanceSignal {
  code: string
  label: string
  weight: number
  evidence: string
}

export interface Vulnerability {
  identifier: string
  title: string
  summary: string
  published_at: string | null
  modified_at: string | null
  vendor: string | null
  product: string | null
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  impact_score: number | null
  exploitability_score: number | null
  attack_vector: string | null
  attack_complexity: string | null
  privileges_required: string | null
  user_interaction: string | null
  scope: string | null
  cvss_metrics: CvssMetric[]
  aliases: string[]
  cwes: string[]
  cpes: string[]
  references: string[]
  reference_details: ReferenceDetail[]
  exploit_references: string[]
  has_exploit: boolean
  cwe_details: Array<{ id: string; source: string | null; type: string | null }>
  affected_products: AffectedProduct[]
  sources: string[]
  kev: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  ransomware_use: string | null
  required_action: string | null
  relevance_score: number
  relevance_level: RelevanceLevel
  relevance_signals: RelevanceSignal[]
  policy_version: string
  is_firmware_related: boolean
  semantic_interface_count: number
  semantic_parameter_count: number
}

export interface CvssMetric {
  version: string
  type: string | null
  source: string | null
  base_score: number | null
  base_severity: string | null
  vector: string | null
  impact_score: number | null
  exploitability_score: number | null
  attack_vector: string | null
  attack_complexity: string | null
  privileges_required: string | null
  user_interaction: string | boolean | null
  scope: string | null
}

export interface ReferenceDetail {
  url: string
  source: string | null
  tags: string[]
}

export interface AffectedProduct {
  criteria: string
  vulnerable: boolean
  match_criteria_id: string | null
  version_start_including: string | null
  version_start_excluding: string | null
  version_end_including: string | null
  version_end_excluding: string | null
}

export interface VulnerabilityPage {
  items: Vulnerability[]
  total: number
  limit: number
  offset: number
  page: number
  pages: number
  has_previous: boolean
  has_next: boolean
}

export interface Overview {
  counts: {
    relevant: number
    critical: number
    kev: number
    exploit: number
  }
  last_updated: string | null
  levels: Array<{ label: RelevanceLevel; value: number }>
  vendors: Array<{ label: string; value: number }>
  recent: Vulnerability[]
}

export interface IntelligenceStatistics {
  counts: { total: number; relevant: number; exploit: number; kev: number; with_cwe: number }
  severity: Array<{ label: string; value: number }>
  cvss_versions: Array<{ label: string; value: number }>
  cwes: Array<{ label: string; value: number }>
  years: Array<{ label: string; value: number }>
}

export interface SyncRun {
  run_id: string
  sources: string[]
  status: 'running' | 'succeeded' | 'failed'
  started_at: string
  finished_at: string | null
  fetched_count: number
  relevant_count: number
  error: string | null
}

export interface RelevancePolicy {
  version: string
  firmware_keywords: string[]
  device_keywords: string[]
  vendor_keywords: string[]
  firmware_only_vendors: string[]
  strong_threshold: number
  likely_threshold: number
  review_threshold: number
}

export interface IntelligenceFilters {
  query: string
  vendor: string
  severity: string
  relevance: string
  kevOnly: boolean
  exploitOnly: boolean
}

export interface FirmwareCatalogOverview {
  counts: {
    source_count: number
    official_source_count: number
    download_host_count: number
    candidate_count: number
    linked_candidate_count: number
    vulnerability_lead_count: number
    exact_version_link_count?: number
    version_range_link_count?: number
    product_scope_link_count?: number
    version_identified_candidate_count?: number
  }
  vendors: Array<{ label: string; value: number }>
  sources: Array<{
    source_id: string
    name: string
    source_type: string
    trust_level: string
    candidate_count: number
  }>
  hosts: Array<{ label: string; value: number }>
}

export interface FirmwareSource {
  source_id: string
  name: string
  source_type: 'official' | 'benchmark' | 'community' | 'archive' | 'advisory'
  base_url: string
  vendor: string | null
  trust_level: 'primary' | 'high' | 'medium' | 'low'
  access_notes: string
  evidence_url: string
  candidate_count: number
  vulnerability_count: number
}

export interface FirmwareCandidate {
  candidate_id: string
  source_id: string
  external_id: string | null
  vendor: string
  product: string
  model: string
  firmware_version: string | null
  filename: string
  download_url: string
  download_host: string
  source_page_url: string
  evidence_url: string
  url_status: 'listed' | 'verified' | 'unverified' | 'restricted' | 'unavailable'
  download_kind: 'direct' | 'portal' | 'repository_directory'
  notes: string
  source_name: string
  source_type: string
  trust_level: string
  vulnerability_count: number
  vulnerability_identifiers: string[]
  version_identities?: Array<{
    raw: string
    normalized: string
    source: 'declared' | 'filename'
    confidence: string
  }>
  version_link_count?: number
  strongest_match_method?: string | null
  association_origin?: 'curated' | 'derived'
  match_method?: 'curated_evidence' | 'exact_version' | 'version_range' | 'product_scope'
  match_score?: number
  candidate_version?: string | null
  affected_constraint?: string | null
  matched_criteria?: string | null
}

export interface FirmwareVulnerabilityLead {
  candidate_id: string
  vulnerability_identifier: string
  relationship: string
  confidence: string
  evidence_url: string
  notes: string
  title: string | null
  vulnerability_vendor: string | null
  vulnerability_product: string | null
  severity: string | null
  cvss_score: number | null
  association_origin: 'curated' | 'derived'
  match_method: 'curated_evidence' | 'exact_version' | 'version_range' | 'product_scope'
  match_score: number
  candidate_version: string | null
  affected_constraint: string | null
  matched_criteria: string | null
}

export interface FirmwareCandidateDetail extends FirmwareCandidate {
  source_base_url: string
  source_access_notes: string
  vulnerabilities: FirmwareVulnerabilityLead[]
}

export interface FirmwareCandidatePage {
  items: FirmwareCandidate[]
  total: number
  limit: number
  offset: number
  page: number
  pages: number
  has_previous: boolean
  has_next: boolean
}

export interface MappingCatalogSummary {
  catalog_id: string
  schema_version: string
  firmware_artifact_sha256: string
  source_inventory_sha256: string
  coverage_status: string
  source_inventory_coverage_status: string
  scheduler_termination: string | null
  published_at: string
  candidate_count: number
  parameter_count: number
  association_count: number
  open_obligation_count: number
  release_context?: MappingReleaseContext | null
}

export interface MappingCorpusSample {
  sample_id: string
  architecture_category: string
  architecture_subtype: string
  role: string
  evidence_tier: 'real_firmware' | 'derived_firmware' | 'contract_fixture' | 'external_lead'
  status: 'verified' | 'derived_only' | 'contract_only' | 'coverage_gap' | 'acquisition_gap'
  catalog_id: string | null
  required_capabilities: string[]
  forbidden_capabilities: string[]
  observed_capabilities: string[]
  missing_capabilities: string[]
  unexpected_capabilities: string[]
  candidate_kinds: string[]
  candidate_count: number
  evidence_count: number
  open_obligation_count: number
  scope_candidate_ids: string[]
}

export interface MappingCorpusCategory {
  architecture_category: string
  status: MappingCorpusSample['status']
  sample_count: number
  real_firmware_verified_count: number
  derived_firmware_verified_count: number
  contract_verified_count: number
  coverage_gap_count: number
  acquisition_gap_count: number
  observed_capabilities: string[]
  candidate_kinds: string[]
  open_obligation_count: number
}

export interface MappingCorpusReport {
  schema_version: string
  capability_policy_version: string
  report_id: string
  corpus_version: string
  gate_status: 'passed' | 'partial' | 'failed'
  required_categories: string[]
  samples: MappingCorpusSample[]
  categories: MappingCorpusCategory[]
}

export interface FirmwareMappingJob {
  schema_version: string
  job_id: string
  original_filename: string
  firmware_artifact_sha256: string
  artifact_size: number
  runner_id: string
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed'
  submitted_at: string
  started_at: string | null
  finished_at: string | null
  artifact_analysis_id: string | null
  catalog_id: string | null
  graph_id: string | null
  error_code: string | null
}

export interface FirmwareMappingJobPage {
  enabled: boolean
  max_upload_bytes: number
  items: FirmwareMappingJob[]
}

export interface MappingReasoningProposal {
  proposal_id: string
  kind: 'analysis_step' | 'candidate_relation' | 'parameter_alias' | 'conflict_explanation' | 'missing_evidence'
  target_ref: string
  summary: string
  rationale: string
  cited_evidence_ids: string[]
  required_corroboration: string
  confidence: number
  status: 'model_suggested'
}

export interface MappingReasoningRun {
  schema_version: string
  run_id: string
  catalog_id: string
  firmware_artifact_sha256: string
  adapter_id: string
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed'
  submitted_at: string
  attempt: number
  started_at: string | null
  finished_at: string | null
  proposals: MappingReasoningProposal[]
  rejected_proposal_count: number
  prompt_tokens: number
  completion_tokens: number
  response_model?: string | null
  provider_request_id?: string | null
  provider_trace_id?: string | null
  error_code: string | null
  diagnostics: string[]
}

export interface MappingReasoningCapability {
  enabled: boolean
  adapter_id: string | null
  latest: MappingReasoningRun | null
}

export interface MappingReleaseContext {
  vendor: string
  product: string
  device_model: string
  firmware_version: string
  source_ref: string
  evidence: string
}

export interface MappingCandidate {
  candidate_id: string
  candidate_kind: string
  canonical_identity: string
  claim_status: string
  source_path: string
  source_construct: string
  evidence_ids: string[]
  attributes: Array<[string, string]>
  parameter_count: number
  association_count: number
  open_obligation_count: number
}

export interface MappingCandidateDetail {
  catalog: {
    catalog_id: string
    coverage_status: string
    source_inventory_coverage_status: string
    scheduler_termination: string | null
  }
  candidate: MappingCandidate
  parameters: Array<{
    parameter_id: string; name: string; namespace: string; literal_value: string | null
    selector_values: string[]; is_operation_selector: boolean; source_construct: string
  }>
  associations: Array<{
    association_id: string; frontend_candidate_id: string; native_hint_id: string
    match_basis: string; evidence_ids: string[]
  }>
  related_candidates: MappingCandidate[]
  open_obligations: Array<{
    obligation_id: string; target_ref: string; status: string; reason: string
    required_capability?: string; priority?: number; candidate_analyzers?: string[]
  }>
  evidence_atoms: Array<{
    evidence_id: string; predicate: string; object_value: string; capability: string
    source_span: { artifact_path: string; locator: string }
  }>
  coverage: Array<{ scope: string; producer_kind: string; producer: string; status: string }>
}

export interface MappingCandidatePage {
  items: MappingCandidate[]
  total: number
  limit: number
  offset: number
}

export interface PotentialHiddenInterface {
  interface_id: string
  catalog_id: string
  firmware_artifact_sha256: string
  operation_token: string
  attribution_id: string
  registration_artifact_path: string
  binding_ids: string[]
  handler_identities: string[]
  frontend_coverage_scopes: string[]
  frontend_coverage_complete: boolean
  runtime_reachability_verified: boolean
  interpretation: string
  open_obligation: string
  evidence_ids: string[]
}

export interface PotentialHiddenInterfacePage {
  items: PotentialHiddenInterface[]
  total: number
  limit: number
  offset: number
  summary: {
    firmware_count: number
    handler_count: number
    eligible_firmware_count: number
    coverage_gap_firmware_count: number
  }
  distributions: {
    firmware: Array<{
      firmware_artifact_sha256: string; catalog_id: string; count: number
    }>
    artifact: Array<{ path: string; count: number }>
  }
}

export interface MappingSnapshotChange {
  change_id: string
  category: 'candidate' | 'parameter' | 'coverage' | 'potential_hidden_interface'
  stable_identity: string
  display_identity: string
  change_kind: 'added' | 'removed' | 'changed'
  confidence: 'firmware_change_supported' | 'observed_scope_only' | 'coverage_confounded'
  changed_fields: string[]
  base: Record<string, unknown> | null
  target: Record<string, unknown> | null
  interpretation: string
}

export interface MappingSnapshotDiff {
  schema_version: string
  comparison_id: string
  base: { catalog_id: string; firmware_artifact_sha256: string; release_context?: MappingReleaseContext | null }
  target: { catalog_id: string; firmware_artifact_sha256: string; release_context?: MappingReleaseContext | null }
  comparison_status: 'coverage_equivalent' | 'coverage_equivalent_partial' | 'coverage_confounded'
  same_firmware_family_verified: boolean
  summary: {
    added_candidate_count: number
    removed_candidate_count: number
    changed_candidate_count: number
    added_parameter_count: number
    removed_parameter_count: number
    changed_parameter_count: number
    discovered_hidden_interface_count: number
    resolved_hidden_interface_count: number
    changed_hidden_interface_count: number
    coverage_change_count: number
    total_change_count: number
  }
  changes: MappingSnapshotChange[]
  diagnostics: Array<{ code: string; message: string }>
}

export interface CommunicationGraphSummary {
  graph_id: string
  schema_version: string
  source_catalog_id: string
  firmware_artifact_sha256: string
  source_catalog_coverage_status: string
  projection_status: string
  node_count: number
  edge_count: number
  published_at: string
}

export interface CommunicationGraphQueryOptions {
  query?: string
  preset?: string
  nodeKinds?: string[]
  edgeKinds?: string[]
  statuses?: string[]
  evidenceId?: string
  focusNodeIds?: string[]
  focusIdentities?: string[]
  maxHops?: number
  maxNodes?: number
  maxEdges?: number
}

export interface CommunicationGraphNode {
  node_id: string
  node_kind: string
  label: string
  status: string
  source_path: string
  evidence_ids: string[]
  attributes: Array<[string, string]>
}

export interface CommunicationGraphEdge {
  edge_id: string
  edge_kind: string
  source_ref: string
  target_ref: string
  status: string
  origin_ref: string
  evidence_ids: string[]
  attributes: Array<[string, string]>
}

export interface CommunicationGraphEvidenceAtom {
  evidence_id: string
  subject_ref: string
  predicate: string
  object_value: string
  capability: string
  confidence: number
  observation_kind: string
  producer: string
  producer_version: string
  source_span: {
    artifact_path: string
    artifact_sha256: string
    locator: string
    span_kind: string
    start_byte: number
    end_byte: number
    start_line?: number | null
    end_line?: number | null
  }
}

export interface CommunicationGraphQueryResult {
  schema_version: string
  query_id: string
  graph: {
    graph_id: string
    schema_version: string
    source_catalog_id: string
    firmware_artifact_sha256: string
    source_catalog_coverage_status: string
    projection_status: string
  }
  query: {
    text: string
    preset_id: string
    node_kinds: string[]
    edge_kinds: string[]
    statuses: string[]
    evidence_id: string
    focus_node_ids: string[]
    focus_canonical_identities: string[]
    max_hops: number
    max_nodes: number
    max_edges: number
  }
  query_status: 'completed' | 'partial'
  nodes: CommunicationGraphNode[]
  edges: CommunicationGraphEdge[]
  total_node_count: number
  total_edge_count: number
  selected_node_count: number
  selected_edge_count: number
  evidence_atoms: CommunicationGraphEvidenceAtom[]
  facets: {
    node_kinds: Record<string, number>
    edge_kinds: Record<string, number>
    statuses: Record<string, number>
  }
  coverage: Array<{
    scope: string
    producer_kind: string
    producer: string
    producer_version: string
    status: string
    required: boolean
    processed_result_count: number
    diagnostic: string
  }>
  view_presets: Array<{
    preset_id: string
    title: string
    node_kinds: string[]
    edge_kinds: string[]
    description: string
  }>
  diagnostics: string[]
}

export interface HistoricalGraphOverlayEntry {
  expectation_id: string
  vulnerability_identifier: string
  interface_value: string
  method: string
  handler_value: string
  expected_parameters: string[]
  source_ref: string
  applicability: 'exact_artifact' | 'product_family' | 'unknown' | 'out_of_scope'
  claimed_versions: string[]
  applicability_basis: string
  status: 'observed' | 'partial' | 'missing' | 'not_assessable'
  gap_reason: string
  gap_explanation: string
  observed_methods: string[]
  observed_parameters: string[]
  missing_parameters: string[]
  catalog_candidate_ids: string[]
  catalog_evidence_ids: string[]
  route_binding_status: string | null
  observed_handlers: string[]
  graph_node_ids: string[]
  graph_edge_ids: string[]
  graph_link_bases: string[]
  unmapped_catalog_reference_ids: string[]
  unmapped_catalog_evidence_ids: string[]
}

export interface HistoricalGraphOverlayQueryResult {
  schema_version: string
  query_id: string
  overlay: {
    schema_version: string
    overlay_id: string
    graph_id: string
    catalog_id: string
    expectation_diff_id: string
    route_binding_report_id: string | null
    claim_boundary: string
    summary: Record<string, Record<string, number>>
    vulnerability_audit: {
      audit_id: string
      total_vulnerability_count: number
      category_counts: Record<string, number>
      exact_artifact_expectation_count: number
      exact_artifact_observed_count: number
    } | null
  }
  query: {
    text: string
    statuses: string[]
    applicabilities: string[]
    gap_reasons: string[]
    route_binding_statuses: string[]
  }
  entries: HistoricalGraphOverlayEntry[]
  total_entry_count: number
  selected_entry_count: number
  facets: {
    status: Record<string, number>
    applicability: Record<string, number>
    gap_reason: Record<string, number>
    route_binding_status: Record<string, number>
  }
  diagnostics: string[]
}

export interface HistoricalCoverageLedgerEntry {
  vulnerability_identifier: string
  audit_category: 'compared_interface' | 'parameter_only' | 'no_structured_communication' | 'not_analyzed'
  status: 'observed' | 'partial' | 'not_found' | 'not_assessable'
  reason_codes: string[]
  reason_explanations: string[]
  action: string
  evidence_state: string
  applicabilities: string[]
  claimed_versions: string[]
  applicability_bases: string[]
  interface_values: string[]
  methods: string[]
  handler_values: string[]
  expected_parameters: string[]
  observed_parameters: string[]
  missing_parameters: string[]
  configuration_keys: string[]
  source_refs: string[]
  catalog_candidate_ids: string[]
  catalog_evidence_ids: string[]
  graph_node_ids: string[]
  graph_edge_ids: string[]
}

export interface HistoricalCoverageLedgerQueryResult {
  schema_version: string
  query_id: string
  ledger: {
    schema_version: string
    ledger_id: string
    graph_id: string
    catalog_id: string
    overlay_id: string
    queue_id: string
    audit_id: string
    total_vulnerability_count: number
    claim_boundary: string
    summary: Record<string, Record<string, number>>
  }
  query: {
    text: string
    statuses: string[]
    audit_categories: string[]
    evidence_states: string[]
  }
  entries: HistoricalCoverageLedgerEntry[]
  total_entry_count: number
  selected_entry_count: number
  facets: {
    status: Record<string, number>
    audit_category: Record<string, number>
    evidence_state: Record<string, number>
  }
}

export interface SemanticInterfaceObservation {
  value: string
  kind: string
  method: string | null
  protocol: string | null
  component: string | null
  confidence: number
  evidence: string
  source: 'rules' | 'llm'
}

export interface SemanticParameterObservation {
  name: string
  interface: string | null
  location: string | null
  security_effect: string | null
  confidence: number
  evidence: string
  source: 'rules' | 'llm'
}

export interface SemanticAnalysis {
  analysis_id: string
  vulnerability_identifier: string
  input_sha256: string
  analyzer_fingerprint: string
  strategy: 'rules' | 'hybrid'
  status: 'succeeded' | 'partial' | 'failed'
  warning: string | null
  prompt_tokens: number
  completion_tokens: number
  created_at: string
  finished_at: string
  cached?: boolean
  result: {
    vulnerability_identifier: string
    interfaces: SemanticInterfaceObservation[]
    parameters: SemanticParameterObservation[]
    attack_type: string | null
    remotely_exploitable: boolean | null
    analyzer_version: string
  }
}

export interface SemanticOverview {
  total: number
  analyzed: number
  pending: number
  interfaces: number
  parameters: number
  prompt_tokens: number
  completion_tokens: number
  top_interfaces: Array<{ label: string; value: number }>
  top_parameters: Array<{ label: string; value: number }>
}

export interface SemanticJob {
  job_id: string
  status: 'running' | 'succeeded' | 'failed'
  strategy: 'rules' | 'hybrid'
  force: number
  total_count: number
  processed_count: number
  analyzed_count: number
  cached_count: number
  failed_count: number
  interfaces_count: number
  parameters_count: number
  started_at: string
  finished_at: string | null
  error: string | null
}

export interface SemanticModelSettings {
  enabled: boolean
  base_url: string
  model: string
  timeout_seconds: number
  temperature: number
  max_tokens: number
  has_api_key: boolean
  active: boolean
}

export type SemanticExploreKind = 'interface' | 'parameter' | 'category'

export interface SemanticCatalogItem {
  value: string
  category: string
  subtype?: string | null
  subtype_label?: string | null
  kind?: string | null
  method?: string | null
  protocol?: string | null
  component?: string | null
  interface_value?: string | null
  location?: string | null
  security_effect?: string | null
  occurrence_count: number
  vulnerability_count: number
  vendor_count: number
  vendors: string[]
  latest_at: string | null
}

export interface SemanticCategory {
  key: string
  label: string
  description: string
  tone: string
  interface_count: number
  vulnerability_count: number
  vendor_count: number
  firmware_count: number
  vendors: string[]
  latest_at: string | null
  top_interfaces: Array<{ value: string; value_count: number }>
}

export interface SemanticAssociation {
  identifier: string
  title: string
  summary: string
  published_at: string | null
  modified_at: string | null
  vendor: string | null
  product: string | null
  severity: string | null
  cvss_score: number | null
  cpes: string[]
  matched_values: string
  semantic_evidence: string
  semantic_confidence: number
  firmware_model: FirmwareModel
}

export interface FirmwareModel {
  key: string
  label: string
  vendor: string
  model: string
  version_summary: string
  source: 'description' | 'cpe'
  alignment: 'aligned' | 'description_primary' | 'cpe_fallback'
  vulnerability_count?: number
}

export interface SemanticSubtype {
  key: string
  label: string
  description: string
  interface_count: number
  vulnerability_count: number
  vendor_count: number
  model_count: number
  examples: Array<{ value: string; vulnerability_count: number }>
}

export interface SemanticCategoryProfile extends SemanticCategory {
  subtypes: SemanticSubtype[]
  active_subtype?: Pick<SemanticSubtype, 'key' | 'label' | 'description'> | null
  scope_interface_count: number
  scope_vulnerability_count: number
  scope_vendor_count: number
  scope_model_count: number
  top_vendors: Array<{ vendor: string; vulnerability_count: number; model_count: number }>
  top_models: FirmwareModel[]
}

export interface InterfaceStructureRecommendation {
  items: Array<SemanticCatalogItem & {
    similarity_score: number
    similarity_signals: string[]
    match_tier?: 'exact' | 'substring' | 'keyword' | 'architecture'
  }>
  total: number
  limit: number
  offset: number
  page: number
  pages: number
  has_previous: boolean
  has_next: boolean
  selection: {
    value: string
    normalized_value: string
    observed: boolean
    category: Pick<SemanticCategory, 'key' | 'label' | 'description'>
    architecture: { key: string; label: string; description: string }
    rationale: string[]
  }
  scope: {
    interface_count: number
    vulnerability_count: number
    vendor_count: number
    model_count: number
  }
  related_vendors: Array<{ vendor: string; vulnerability_count: number; model_count: number }>
  related_firmware: FirmwareModel[]
  related_vulnerabilities: Array<{
    identifier: string
    title: string
    summary: string
    vendor: string | null
    product: string | null
    severity: string | null
    cvss_score: number | null
    published_at: string | null
    modified_at: string | null
  }>
}

export interface SemanticExplorePage<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  page: number
  pages: number
  has_previous: boolean
  has_next: boolean
  selection?: Record<string, unknown>
}
