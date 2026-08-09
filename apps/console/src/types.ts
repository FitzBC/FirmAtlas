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
