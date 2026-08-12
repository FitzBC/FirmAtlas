#!/usr/bin/env python3
"""Build deterministic, paper-oriented communication-mapping case records."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    CaseClaim,
    CaseClaimStatus,
    CaseEvidenceKind,
    CaseEvidenceReference,
    CaseObligation,
    CaseObligationStatus,
    CaseStage,
    ResearchCaseInput,
    build_research_case,
    validate_research_case_corpus,
)


AC9_FIRMWARE_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
HTTPD_SHA256 = "2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b"
X5000R_FIRMWARE_SHA256 = "2acd661c22b0ca4467af24931864946b8b6ded772ec24a8601d30aea2436ade9"
AC9_R2_10_REPORT = Path(
    "docs/firmware-mapping/samples/r2-10-vendor-tenda-ac9-response-fixtures.json"
)
AC9_R2_11_REPORT = Path(
    "docs/firmware-mapping/samples/r2-11-vendor-tenda-ac9-native-relationships.json"
)
AC9_R2_12_REPORT = Path(
    "docs/firmware-mapping/samples/r2-12-vendor-tenda-ac9-daemon-command-chain.json"
)
AC9_R2_13_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-13-vendor-tenda-ac9-tail-merged-usb-status.json"
)
AC9_R2_14_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-14-vendor-tenda-ac9-disabled-dlna-feature.json"
)
AC9_R2_15_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-15-vendor-tenda-ac9-ac18-dlna-feature-pivot.json"
)
AC9_R2_16_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json"
)
AC9_R2_17_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-17-vendor-tenda-ac9-ac18-dlna-communication-graph.json"
)
AC9_R2_18_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-18-vendor-tenda-ac9-graph-query.json"
)
AC9_R2_19_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-19-vendor-tenda-ac9-http-console-graph.json"
)
AC9_R2_20_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-20-vendor-tenda-ac9-historical-graph-overlay.json"
)
AC9_R2_21_QUEUE = Path(
    "docs/firmware-mapping/samples/"
    "r2-21-vendor-tenda-ac9-historical-coverage-queue.json"
)
AC9_R2_21_REPLAY = Path(
    "docs/firmware-mapping/samples/"
    "r2-21-vendor-tenda-ac9-historical-replay.json"
)
AC9_R2_22_INGRESS = Path(
    "docs/firmware-mapping/samples/"
    "r2-22-vendor-tenda-ac9-configuration-ingress.json"
)
AC9_R2_23_PERSISTENCE = Path(
    "docs/firmware-mapping/samples/"
    "r2-23-vendor-tenda-ac9-cross-elf-persistence.json"
)


def build_ac9_split_web_stack_case():
    """Preserve the evidence progression from namespace gap to native binding."""

    history_report_sha = hashlib.sha256(AC9_R2_20_REPORT.read_bytes()).hexdigest()
    history_overlay_ref = CaseEvidenceReference(
        "coverage:ac9-historical-graph-overlay",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_20_REPORT.as_posix(),
        history_report_sha,
        "json:$.historical_comparison",
        "compares_historical_expectations_without_fact_promotion",
        "historical-graph-overlay@v1alpha1",
    )
    history_queue_sha = hashlib.sha256(AC9_R2_21_QUEUE.read_bytes()).hexdigest()
    history_queue_ref = CaseEvidenceReference(
        "coverage:ac9-historical-coverage-queue",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_21_QUEUE.as_posix(),
        history_queue_sha,
        "json:$",
        "prioritizes_unstructured_historical_communication_gaps",
        "historical-coverage-queue@v1alpha1",
    )
    history_replay_sha = hashlib.sha256(AC9_R2_21_REPLAY.read_bytes()).hexdigest()
    history_replay_ref = CaseEvidenceReference(
        "coverage:ac9-historical-expectation-replay-r2-21",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_21_REPLAY.as_posix(),
        history_replay_sha,
        "json:$",
        "replays_source_verified_expectations_against_current_catalog",
        "historical-expectation-diff@v1alpha1",
    )
    ingress_sha = hashlib.sha256(AC9_R2_22_INGRESS.read_bytes()).hexdigest()
    ingress_ref = CaseEvidenceReference(
        "coverage:ac9-configuration-ingress-r2-22",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_22_INGRESS.as_posix(),
        ingress_sha,
        "json:$.automated_chain",
        "binds_configuration_ingress",
        "native-arm-cgi-string-dispatch@0.1.0",
    )
    persistence_sha = hashlib.sha256(AC9_R2_23_PERSISTENCE.read_bytes()).hexdigest()
    persistence_ref = CaseEvidenceReference(
        "coverage:ac9-cross-elf-persistence-r2-23",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_23_PERSISTENCE.as_posix(),
        persistence_sha,
        "json:$.selected_calls",
        "binds_configuration_persistence",
        "native-arm-cross-elf-call@0.1.0",
    )

    return build_research_case(ResearchCaseInput(
        case_key="tenda-ac9-split-web-stack-goform-ownership",
        title="Tenda AC9: split nginx/FastCGI and native goform backends",
        firmware_artifact_sha256=AC9_FIRMWARE_SHA256,
        architecture_tags=(
            "split_web_stack",
            "nginx_fastcgi_sidecar",
            "goform_camel_registry",
            "arm_pic_registration",
        ),
        research_question=(
            "When nginx exposes only /cgi-bin/luci/ and /download/, which binary "
            "actually owns the frontend-observed /goform operations?"
        ),
        evidence=(
            CaseEvidenceReference(
                "evidence:21b00efacd8603336bf79a222508fb50cfcf290ff3f2a70613b07d2150f2724c",
                CaseEvidenceKind.FRONTEND_REQUEST,
                "webroot_ro/js/online_list.js",
                "dd06a5b73cfd64686e5faaf497784190ac5b06801d9f6beb3fb8d90b7bf5cf87",
                "text_utf8:bytes=8902-8925;lines=293:10-293:33",
                "constructs_request",
                "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:a0da24eeb4bf15b945e4e22ec43809393277d3e894d8fc5477dd9152523b8f5e",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=703-707;lines=36:22-36:26",
                "listens_on",
                "web-configuration-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:5e3cbb6617a5d9733512054d473bfe1eefd9ea35c5169f9b6428f416c5290a29",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=971-985;lines=49:17-49:31",
                "maps_namespace",
                "web-configuration-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:24b22b2b30f09ac9486cf461f223e93f1455bee974ba2d22055985cd4e291cd2",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx_init.sh",
                "c1e33c019efab0ac120c99c0abf8b66bbbdb6b64ba2ea855abcace257195b9a1",
                "text_utf8:bytes=114-138;lines=6:33-6:57",
                "starts",
                "web-configuration-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:b63bed9e6504f0d6467d6a85cff55e4df243325d8cbb0a71868ae1236e836048",
                CaseEvidenceKind.NATIVE_HINT,
                "bin/httpd",
                HTTPD_SHA256,
                "binary:bytes=874584-874600",
                "mentions_endpoint",
                "native-shallow-producer@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:dhttpd-selected-components-0-of-6",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "bin/dhttpd",
                "df31d8a86065c2292d6281e16653c6f0d61474265befc9ad55f4860532dad79b",
                "coverage:complete-native-shallow;selected_action_components=0/6",
                "bounds_candidate_search",
                "native-shallow-producer@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:93147f41fefb653b38dc9ad0ee3833bd129f16f4a3e7ede8ca2524e9c770ce2e",
                CaseEvidenceKind.NATIVE_BINDING,
                "bin/httpd",
                HTTPD_SHA256,
                "binary:bytes=240340-240368",
                "registers_route",
                "native-deep-arm-pic-callsite@0.1.0",
            ),
            history_overlay_ref,
            history_queue_ref,
            history_replay_ref,
            ingress_ref,
            persistence_ref,
            CaseEvidenceReference(
                "evidence:a5b3ee3a7fc2b3abaf51d76517e5efd4fd919f9f8ca0559dcd71cb570f289cb5",
                CaseEvidenceKind.NATIVE_BINDING,
                "bin/httpd",
                HTTPD_SHA256,
                "binary:bytes=240340-240368",
                "binds_handler",
                "native-deep-arm-pic-callsite@0.1.0",
            ),
        ),
        claims=(
            CaseClaim(
                "claim:frontend-goform",
                "The web UI constructs POST goform/SetOnlineDevName.",
                ("evidence:21b00efacd8603336bf79a222508fb50cfcf290ff3f2a70613b07d2150f2724c",),
            ),
            CaseClaim(
                "claim:fastcgi-branch",
                "A distinct nginx branch listens on :8180 and forwards "
                "/cgi-bin/luci/ to 127.0.0.1:8188, where app_data_center is started.",
                (
                    "evidence:a0da24eeb4bf15b945e4e22ec43809393277d3e894d8fc5477dd9152523b8f5e",
                    "evidence:5e3cbb6617a5d9733512054d473bfe1eefd9ea35c5169f9b6428f416c5290a29",
                    "evidence:24b22b2b30f09ac9486cf461f223e93f1455bee974ba2d22055985cd4e291cd2",
                ),
            ),
            CaseClaim(
                "claim:historical-interface-scope-boundary",
                "The exact AC9 artifact observes all three exact-artifact historical "
                "interface expectations, while cross-version structural matches "
                "remain independently labeled out_of_scope and do not assert "
                "vulnerability presence.",
                (
                    history_overlay_ref.evidence_ref,
                    history_replay_ref.evidence_ref,
                ),
            ),
            CaseClaim(
                "claim:historical-field-type-boundary",
                "Primary-source replay upgrades CVE-2021-42659 to an observed "
                "POST interface with body:list, but keeps security.ddos.map and "
                "sys.schedulereboot.* as configuration keys behind unresolved "
                "ingress rather than promoting them to HTTP parameters.",
                (history_queue_ref.evidence_ref,),
            ),
            CaseClaim(
                "claim:configuration-upload-cgi-owner",
                "POST /cgi-bin/UploadCfg carries multipart form field filename; "
                "an independent ARM string-switch dispatcher at 0x3a9a0 binds "
                "UploadCfg to bin/httpd@0x3b850 with a six-entry family proof.",
                (ingress_ref.evidence_ref,),
            ),
            CaseClaim(
                "claim:configuration-persistence-chain",
                "Verified ARM PLT calls and dynamic exports connect UploadCfg's "
                "handler to tpi_sys_cfg_upload, while gCtlCmdArr binds command "
                "Upload to UploadValue and its SendMsg/RecvMsg IPC pair. The "
                "doSystemCmd call preserves literal cfm Upload but leaves its "
                "ambiguous implementation owner unresolved.",
                (persistence_ref.evidence_ref,),
            ),
            CaseClaim(
                "claim:namespace-divergence",
                "The observed nginx namespaces do not establish ownership of "
                "/goform; backend ownership must remain unresolved at this stage.",
                (
                    "evidence:21b00efacd8603336bf79a222508fb50cfcf290ff3f2a70613b07d2150f2724c",
                    "evidence:5e3cbb6617a5d9733512054d473bfe1eefd9ea35c5169f9b6428f416c5290a29",
                ),
                CaseClaimStatus.UNRESOLVED,
            ),
            CaseClaim(
                "claim:shallow-priority",
                "Exact action-component evidence prioritizes httpd over dhttpd, "
                "but does not yet prove a handler binding.",
                (
                    "evidence:b63bed9e6504f0d6467d6a85cff55e4df243325d8cbb0a71868ae1236e836048",
                    "coverage:dhttpd-selected-components-0-of-6",
                ),
                CaseClaimStatus.UNRESOLVED,
            ),
            CaseClaim(
                "claim:httpd-handler-binding",
                "ARM PIC call-site validation proves SetOnlineDevName is registered "
                "by bin/httpd and bound to formSetDeviceName at 0x00060ee8.",
                (
                    "evidence:93147f41fefb653b38dc9ad0ee3833bd129f16f4a3e7ede8ca2524e9c770ce2e",
                    "evidence:a5b3ee3a7fc2b3abaf51d76517e5efd4fd919f9f8ca0559dcd71cb570f289cb5",
                ),
            ),
        ),
        stages=(
            CaseStage(
                "stage:frontend-request", 1,
                "Recover the externally visible operation without guessing its backend.",
                ("claim:frontend-goform",),
            ),
            CaseStage(
                "stage:configuration-separation", 2,
                "Publish the nginx/FastCGI chain as a separate branch and retain "
                "ownership as an obligation.",
                ("claim:fastcgi-branch", "claim:namespace-divergence"),
                creates_obligations=("obligation:goform-owner",),
            ),
            CaseStage(
                "stage:native-candidate-ranking", 3,
                "Use bounded shallow evidence to select a deep-analysis target, "
                "not to publish a binding.",
                ("claim:shallow-priority",),
            ),
            CaseStage(
                "stage:native-callsite-proof", 4,
                "Require route and handler arguments at the same validated registrar "
                "call-site before resolving ownership.",
                ("claim:httpd-handler-binding",),
                resolves_obligations=("obligation:goform-owner",),
            ),
            CaseStage(
                "stage:historical-interface-overlay", 5,
                "Project historical interfaces and parameters onto exact graph "
                "references while preserving applicability as an independent "
                "dimension and leaving firmware facts unchanged.",
                ("claim:historical-interface-scope-boundary",),
            ),
            CaseStage(
                "stage:historical-coverage-priority-queue", 6,
                "Classify the remaining 57 non-compared vulnerability records, "
                "repair a false natural-language parameter, separate native "
                "configuration keys from HTTP fields, and retain unknown ingress "
                "as an explicit obligation.",
                ("claim:historical-field-type-boundary",),
                creates_obligations=("obligation:configuration-ingress",),
            ),
            CaseStage(
                "stage:configuration-upload-cgi-dispatch", 7,
                "Reject the ordinary websForm registrar hypothesis, validate the "
                "separate CGI token switch, and bind the multipart request to its "
                "direct native handler without promoting configuration keys to "
                "HTTP fields.",
                ("claim:configuration-upload-cgi-owner",),
                creates_obligations=("obligation:configuration-persistence-link",),
                resolves_obligations=("obligation:configuration-ingress",),
            ),
            CaseStage(
                "stage:configuration-cross-elf-persistence", 8,
                "Resolve verified PLT imports only through current or dependency-"
                "qualified exports, recover the exact cfm Upload call argument, "
                "and connect the symbol-sized command table to Cfm IPC without "
                "inventing an owner for an ambiguous same-name export.",
                ("claim:configuration-persistence-chain",),
                creates_obligations=("obligation:configuration-key-parser",),
                resolves_obligations=("obligation:configuration-persistence-link",),
            ),
        ),
        obligations=(
            CaseObligation(
                "obligation:goform-owner",
                "Identify the binary and handler that register the /goform operation.",
                "binds_handler",
                CaseObligationStatus.RESOLVED,
                (
                    "evidence:93147f41fefb653b38dc9ad0ee3833bd129f16f4a3e7ede8ca2524e9c770ce2e",
                    "evidence:a5b3ee3a7fc2b3abaf51d76517e5efd4fd919f9f8ca0559dcd71cb570f289cb5",
                ),
            ),
            CaseObligation(
                "obligation:configuration-ingress",
                "Recover the HTTP upload/import path that writes the configuration "
                "keys later consumed by the DDoS and reboot handlers.",
                "binds_configuration_ingress",
                CaseObligationStatus.RESOLVED,
                (ingress_ref.evidence_ref,),
            ),
            CaseObligation(
                "obligation:configuration-persistence-link",
                "Automate the handler-to-libtpi-to-cfm IPC chain and model the "
                "uploaded configuration as a wildcard state-write surface.",
                "binds_configuration_persistence",
                CaseObligationStatus.RESOLVED,
                (persistence_ref.evidence_ref,),
            ),
            CaseObligation(
                "obligation:configuration-key-parser",
                "Recover the uploaded blob parser and key-level persistence flow; "
                "until then retain a wildcard configuration-state write surface.",
                "binds_configuration_key_parser",
                CaseObligationStatus.OPEN,
            ),
        ),
        counterfactuals=(
            "A firmware-level or path-style merge would incorrectly assign /goform "
            "to the observed nginx/FastCGI namespace.",
            "Choosing dhttpd by filename alone would spend deep-analysis effort on "
            "the weaker candidate.",
            "Treating a route string and a similar symbol name as a binding would "
            "skip the registrar call-site proof.",
            "Treating a cross-version historical interface match as a current "
            "vulnerability would collapse structural observation, version "
            "applicability, and exploitability into one unsupported claim.",
            "Treating a native configuration key as an HTTP request parameter "
            "would fabricate a direct ingress edge and conceal the missing upload chain.",
            "Assuming every /cgi-bin operation uses websFormDefine would miss the "
            "independent UploadCfg/DownloadCfg string-switch dispatcher.",
        ),
        paper_uses=(
            "Motivating case for why communication mapping must precede "
            "target-binary vulnerability analysis.",
            "Ablation case comparing frontend-only, configuration-only, "
            "shallow-native, and full evidence fusion.",
            "Worked example for obligation-preserving analysis and false-merge prevention.",
            "Historical-ground-truth overlay example separating mapper recall "
            "from firmware-version vulnerability conclusions.",
            "Typed historical-field case showing why request parameters, route "
            "tokens, configuration keys, and inferred paths need separate states.",
            "Architecture-split case where a second dispatcher family changes an "
            "obligation from unknown ingress to known owner plus open persistence.",
        ),
        limitations=(
            "The native result proves selected static registrations, not runtime "
            "reachability or authentication state.",
            "Historical expectation coverage is limited to 14 structured "
            "interfaces from a 71-record product-level denominator and is not a "
            "vulnerability or exploitability audit of the artifact.",
            "The dhttpd negative control is bounded by the declared shallow producer "
            "and is not proof of total runtime non-participation.",
            "One firmware case motivates and illustrates the method but cannot "
            "establish cross-vendor generality.",
        ),
    ))


def build_x5000r_shared_cgi_case():
    """Preserve shared-CGI dispatch and cross-binary protection scope."""

    return build_research_case(ResearchCaseInput(
        case_key="totolink-x5000r-shared-cgi-selector-dispatch",
        title="TOTOLINK X5000R: one CGI endpoint, multiple logical operations",
        firmware_artifact_sha256=X5000R_FIRMWARE_SHA256,
        architecture_tags=(
            "lighttpd_cgi", "shared_cgi_dispatcher", "json_topicurl_selector",
            "hybrid_query_and_json_dispatch", "custom_session_path_gate",
        ),
        research_question=(
            "How can operations sharing /cgi-bin/cstecgi.cgi be kept distinct, "
            "which native dispatch structure implements each selector, and which "
            "static request-protection gates actually cover that CGI path?"
        ),
        evidence=(
            CaseEvidenceReference(
                "evidence:ac676e494b61634f6a3790c2df35424d851c97b54e4cd45d875f2233c2ec521d",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/config_ie.js",
                "6147395422cc29a9d77628450603d08f58fb8ed8b8b7916701e2eecf41183f0e",
                "text_utf8:bytes=1382-1402;lines=1:1277-1:1297",
                "constructs_request", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:0eef36d58656acdc469c9d18fb9c28443d1d73b03ebdf264130b5dbda1a20e00",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/config_ie.js",
                "6147395422cc29a9d77628450603d08f58fb8ed8b8b7916701e2eecf41183f0e",
                "text_utf8:bytes=1429-1439;lines=1:1324-1:1334",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:d0f3c62891c645bfb8b754b2e96398c38829ce44963a5ec536530c460edd32cc",
                CaseEvidenceKind.WEB_CONFIGURATION, "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=5556-5560;lines=147:31-147:35",
                "listens_on", "web-configuration-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:bbae0a4136479b40f2b645fee3bdef752d153659122bed6b345d88e21feba878",
                CaseEvidenceKind.WEB_CONFIGURATION, "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=8344-8354;lines=238:2-238:12",
                "binds_handler", "web-configuration-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:af51c25c0f5de49cce076d4851c699b81084a1e9455c67163d3c6ea122f467a1",
                CaseEvidenceKind.NATIVE_HINT, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=233632-233642", "mentions_endpoint",
                "native-shallow-producer@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:340a0168af128fbe29827a9d42f4c5b6687017ad1152d2ed166c46835f962d31",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/topicurl.js",
                "2170e9339adf4c3579ba015f19105c2ec03d1695796881589b0c5b163e059366",
                "text_utf8:bytes=787-806;lines=1:788-1:807",
                "constructs_request", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:f4dbb6c496f66cd5482a332eb3c531765d62e1abe32b50c74c6aa11637011458",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/topicurl.js",
                "2170e9339adf4c3579ba015f19105c2ec03d1695796881589b0c5b163e059366",
                "text_utf8:bytes=2510-2518;lines=1:2511-1:2519",
                "serializes_parameter", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:33ac181ea5411f80f15906f644c74de347614209d73b33e280e412d2970628d4",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/topicurl.js",
                "2170e9339adf4c3579ba015f19105c2ec03d1695796881589b0c5b163e059366",
                "text_utf8:bytes=2520-2529;lines=1:2521-1:2530",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:7fae6c104f1f2dfd69650f3c02b095bfe85bb7f3b25bdd6de54c16919c0e305a",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/config.js",
                "83aa98623d98aeffbcee6748a5c176f2c52bf1e9bdc9e722f111cadc2b31e739",
                "text_utf8:bytes=806-826;lines=1:807-1:827",
                "resolves_endpoint_binding", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:7b8f6bc1380ed52f3b870059b0d9fdf6e31d08c1d6668712397c34f8578f08b5",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=240172-240181", "mentions_endpoint",
                "native-deep-mips-inline-route-table@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:40f4546d6cd758973c602b975270fd34a65952eb0af3480684e4df9c1f1f9b75",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=2008-2024", "resolves_table_symbol",
                "native-deep-mips-inline-route-table@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:aa8f5f7a8b5cad1c0f36a8e6f603f37bd27a49409b107efb9ad8b15dda37c4f5",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=240172-240240", "registers_route",
                "native-deep-mips-inline-route-table@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:6df24edc5d0e4dc1e08efb25e9551a410f8a56acd526181f30ddaa10e1755f88",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=240172-240240", "binds_handler",
                "native-deep-mips-inline-route-table@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-mips-dispatch-set-difference",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-16-x5000r-mips-dispatch.json",
                "cb1c549c5248b5f31f20257f30c0d634dde8e2eee81de43381967f6d1ea37d4f",
                "json:$.counts", "bounds_candidate_search",
                "mips-dispatch-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:65068ce79bc8a710cbe30d9614bdecf0007d3e7d1319432405bab218ff3c9b1d",
                CaseEvidenceKind.NATIVE_VALUE_FLOW, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=133772-133780", "maps_parameter_to_state",
                "native-mips-handler-value-flow@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:1a7119907f1f9f7e8f1e803e58560217703364813025bc453d4fc11e55b4d59f",
                CaseEvidenceKind.NATIVE_VALUE_FLOW, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=133792-133800", "maps_parameter_to_state",
                "native-mips-handler-value-flow@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-setlancfg-handler-prefix",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-17-x5000r-mips-value-flow.json",
                "5dbda7815d736bba9cb2e083748b07cfc0f1f873a46fe77e2606cc0172bbb576",
                "json:$.coverage", "bounds_value_flow_scope",
                "mips-handler-value-flow-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:48c0ae04fd6e114f4f6980da1bf7345aff258957469d8bee893a648e28dc9277",
                CaseEvidenceKind.SET_DIFFERENCE, "www/advance/dos.html",
                "d024fbc7305e5f777b41084e3b3bed3ae3a3169f7d9b6ceccdf18ddca0b0511b",
                "text_utf8:bytes=3306-3315;lines=58:765-58:774",
                "mentions_operation_token", "frontend-native-set-difference@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:4c27b133facef90524fbb2f238c4927c5a5e854543265e1579204ba85f6d75cc",
                CaseEvidenceKind.SET_DIFFERENCE, "www/wan_ie.html",
                "3c6be0fc821f033fc3af38b3b9ee688120b5368a2dc800a560a74c4a9f380820",
                "text_utf8:bytes=10173-10184;lines=1:10174-1:10185",
                "mentions_operation_token", "frontend-native-set-difference@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:df7756729dbf120b10d0460438f7187623d6ce7314d8ce85a75a5a0b8ab5c6a4",
                CaseEvidenceKind.SET_DIFFERENCE, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=11640-11653", "mentions_operation_variant",
                "frontend-native-set-difference@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-set-difference-attribution",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-18-x5000r-set-difference.json",
                "73aa8b4db9fc84792c51db4afd1b1f6d3eddbc56e50123240843a588b3ddaa55",
                "json:$.attribution_counts", "attributes_set_difference",
                "set-difference-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:01b3a330fa09b9fa1f6951ebc6265bb37196e6384a33f1e64534fb69e3c4112a",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/kr.js",
                "a2d27291e824ee0fc8fbad0b0eb23e981ed9db7e07fdf89eb6c301205657e52b",
                "text_utf8:bytes=1519-1539;lines=1:1520-1:1540",
                "resolves_endpoint_binding", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:e312a99e46a58c2daafe389faa164f3d5b4008f1eea34287ddbe66aaaa642177",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/wan_ie.html",
                "3c6be0fc821f033fc3af38b3b9ee688120b5368a2dc800a560a74c4a9f380820",
                "text_utf8:bytes=6447-6458;lines=1:6448-1:6459",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:83bcc17baff831a4f286d1b5286147e068adc965ecf0ba3228ddbee89dc1c0d3",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/wan_ie.html",
                "3c6be0fc821f033fc3af38b3b9ee688120b5368a2dc800a560a74c4a9f380820",
                "text_utf8:bytes=10173-10184;lines=1:10174-1:10185",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:2840a161f73b3015b5e8393dbc88179d70e6439929224f5d900ed45838a409d0",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/advance/config.html",
                "e4ed2ad59c3d574bcf5abcad8a0091aac876e4a72bdb205526944721fd7bffe4",
                "text_utf8:bytes=2377-2393;lines=57:514-57:530",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "evidence:ec15c78cfd749e28153a6b617362e41c678d9009c128ae970b7a1ac0e1af741a",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/advance/config.html",
                "e4ed2ad59c3d574bcf5abcad8a0091aac876e4a72bdb205526944721fd7bffe4",
                "text_utf8:bytes=2362-2368;lines=57:499-57:505",
                "selects_operation", "frontend-request-producer@0.4.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-expanded-frontend-scope",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-19-x5000r-expanded-frontend.json",
                "5232273a6ef7acd70e532a9ef26e96f977712cd296b9034baaae0dd6683245f7",
                "json:$.scope_closure", "closes_frontend_scope_gap",
                "expanded-frontend-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:469a1724198b6c62aa45d85858d7fa6e6d54d720a5010aba54aeff8a637bf53a",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=189852-189876",
                "selects_transport_mode",
                "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:7ba281dfa74b05759b9f20d6a7b84f7abab5dc2f871aab44957b6ba018a5b74a",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=190000-190060",
                "parses_upload_body",
                "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:3d00d3f04153c618cfab025441c125a843bcc2517f50856df7ccbf35b1401bbd",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=190272-190388",
                "constructs_dispatch_payload",
                "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:784717b02a18e526c5a837d5c1302c169a3206d9ce6f91c9f2f38d8b1ff70376",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=190392-190420",
                "normalizes_operation_suffix",
                "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:e03704a5b65ab6cd2113068c5599edc41c799777778b8d7f2cc57a5d601d9ed6",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=190628-190664",
                "selects_dispatch_table",
                "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:266baa8d476660a993a4476f3dc5fa95ecfc29ca2eace7c8c517b77e992f0816",
                CaseEvidenceKind.NATIVE_BINDING, "www/cgi-bin/cstecgi.cgi",
                X5000R_FIRMWARE_SHA256, "binary:bytes=237860-237928",
                "binds_handler", "native-mips-cgi-nested-dispatch@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-nested-upload-dispatch",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-20-x5000r-nested-dispatch.json",
                "f861d9f9de8fddcd24fd0fdcd1f608a99ee4ab0576e22fe2910ba7d48c359c7d",
                "json:$.native_dispatch", "binds_upload_mode",
                "nested-dispatch-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:00078b1dcdbde38a6323e0458697834454e6c0df2d830be7c8d5b9ba7557dc4e",
                CaseEvidenceKind.NATIVE_PROTECTION, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=31380-31520", "selects_protection_scope",
                "native-mips-request-protection@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:e4fd7ac52f78bbddfd1156c1a541216ba013ee05f3fc67a9ed10828ffe6a18ca",
                CaseEvidenceKind.NATIVE_PROTECTION, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=37860-37872", "invokes_authenticator",
                "native-mips-request-protection@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:14672792d961e5f439a7cfb3ba0f1c440d91e52ddf77780781d2cd0e18871801",
                CaseEvidenceKind.NATIVE_PROTECTION, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=35464-35524", "validates_session_cookie",
                "native-mips-request-protection@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:d42f0701efb9ebf7eac1112e34eb916408f873e785db5749caabd87b46d82a90",
                CaseEvidenceKind.NATIVE_PROTECTION, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=31520-31568", "enforces_auth_redirect",
                "native-mips-request-protection@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:36cbf6aae3090fab8d7d27000a90dfb3aeeedea42d2e87ac36ab8d62ec3b6977",
                CaseEvidenceKind.NATIVE_PROTECTION, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=31380-31520", "classifies_request_scope",
                "native-mips-request-protection@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-request-protection",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-21-x5000r-request-protection.json",
                "3d80257d965110ed58bb4b12caadee6e1ee2684183605dd4747f4be666ace030",
                "json:$.protection_analysis", "maps_auth_guard",
                "request-protection-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "evidence:14d3736dfba5d6076335e303471997dde64fe1be5a7ca45eaeb6d0da9186c612",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "sbin/rc",
                "06bb0133c8e84dbe66e5b50d14a2da30f550c5f96c71a2a1c085f3e72ebf1a7c",
                "binary:bytes=36632-36644", "enters_service_bootstrap",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:745154952409e4487d62a5bd8a92df73875de038912cf3fc50bd76c7e57a6624",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "sbin/rc",
                "06bb0133c8e84dbe66e5b50d14a2da30f550c5f96c71a2a1c085f3e72ebf1a7c",
                "binary:bytes=46764-46776", "schedules_service_launcher",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:07a865c5f28c93dfe821511f0a161b700f3a86ddb3412ab59b3a17d24bf5e6b0",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "sbin/rc",
                "06bb0133c8e84dbe66e5b50d14a2da30f550c5f96c71a2a1c085f3e72ebf1a7c",
                "binary:bytes=251880-251927", "defines_service_arguments",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:2ce5ca93095e4ad51bea5c915f181e8042af0a0b39b9a03f36db95e5c6567d64",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "sbin/rc",
                "06bb0133c8e84dbe66e5b50d14a2da30f550c5f96c71a2a1c085f3e72ebf1a7c",
                "binary:bytes=291604-291628", "orders_service_arguments",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:37a6599d2de737e244b5c91fd0a9eafab8c149563efbe22f3e3dfe5142590b34",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "sbin/rc",
                "06bb0133c8e84dbe66e5b50d14a2da30f550c5f96c71a2a1c085f3e72ebf1a7c",
                "binary:bytes=43796-43820", "invokes_service_launcher",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:d2ee6f5d3565fddc127bb6fbc56e7e5524556595c565d05e1d5973d38b5a3341",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY, "usr/sbin/lighttpd",
                "8f2003be1b14f9f3e5567d663918a688b6c6c9f7463466e97778ef5af00729aa",
                "binary:bytes=0-64", "resolves_server_artifact",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:126f5f64cbf2eb921b9629b995345840917a89be9aa73ef44f77b851b4bd9732",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY,
                "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=0-64;lines=1:1-3:33",
                "loads_server_configuration",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:95e5a2899396a30ad920f39c2838dacef0dfc562d716c143141a0a696e8c490d",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY,
                "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=5490-5560;lines=143:30-147:35",
                "exposes_listeners", "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:7760bcc17531bc3d677d9579937aba1b094cf828b4ba366a53e9131051d97d2d",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY,
                "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=5518-5523;lines=145:25-145:30",
                "maps_document_root", "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:99bb5ef14b289639b11eabcfaaa1adf982d25de686ab4a2772fb08edc4b4b063",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY,
                "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=8344-8354;lines=238:2-238:12",
                "binds_cgi_namespace", "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:9f9fb21c6f6d88407ddf0ada7511faccaeec40477e54ca9b26561f90284105cf",
                CaseEvidenceKind.NATIVE_SERVICE_ASSEMBLY,
                "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=0-64", "resolves_request_artifact",
                "native-mips-service-assembly@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-service-assembly",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/m1-22-x5000r-service-assembly.json",
                "24ef2319727e17c37412867b5ef63c4f844ba026c26ccc51e83f27cb9473ca0c",
                "json:$.service_assembly_analysis", "assembles_static_service",
                "service-assembly-report@v1alpha1",
            ),
            CaseEvidenceReference(
                "coverage:x5000r-potential-hidden-interfaces",
                CaseEvidenceKind.COVERAGE_LEDGER,
                "docs/firmware-mapping/samples/"
                "m1-23-x5000r-potential-hidden-interfaces.json",
                "5a2589577f4b643e9ecdb0e0d03cd0bdc8d4bc68a6b8e100a78c7aa319eede7f",
                "json:$.items", "indexes_potential_hidden_interfaces",
                "potential-hidden-interface-report@v1alpha1",
            ),
        ),
        claims=(
            CaseClaim(
                "claim:x5000r-shared-endpoint",
                "The frontend posts JSON operation getInitCfg to /cgi-bin/cstecgi.cgi.",
                (
                    "evidence:ac676e494b61634f6a3790c2df35424d851c97b54e4cd45d875f2233c2ec521d",
                    "evidence:0eef36d58656acdc469c9d18fb9c28443d1d73b03ebdf264130b5dbda1a20e00",
                ),
            ),
            CaseClaim(
                "claim:x5000r-cgi-execution",
                "lighttpd listens on 8080 and enables CGI execution for /cgi-bin/.",
                (
                    "evidence:d0f3c62891c645bfb8b754b2e96398c38829ce44963a5ec536530c460edd32cc",
                    "evidence:bbae0a4136479b40f2b645fee3bdef752d153659122bed6b345d88e21feba878",
                ),
            ),
            CaseClaim(
                "claim:x5000r-native-selector-presence",
                "The MIPS cstecgi.cgi binary contains the getInitCfg selector.",
                ("evidence:af51c25c0f5de49cce076d4851c699b81084a1e9455c67163d3c6ea122f467a1",),
            ),
            CaseClaim(
                "claim:x5000r-cross-resource-endpoint",
                "Asset-graph resolution binds globalConfig.cgiUrl in config.js to the wrapper consumed in topicurl.js and recovers 199 statically enumerated topicurl operations.",
                (
                    "evidence:340a0168af128fbe29827a9d42f4c5b6687017ad1152d2ed166c46835f962d31",
                    "evidence:33ac181ea5411f80f15906f644c74de347614209d73b33e280e412d2970628d4",
                    "evidence:7fae6c104f1f2dfd69650f3c02b095bfe85bb7f3b25bdd6de54c16919c0e305a",
                ),
            ),
            CaseClaim(
                "claim:x5000r-native-handler-binding",
                "At the cross-resource frontend stage, the static topicurl selectors were not yet bound to concrete native handler functions or value-flow paths.",
                (
                    "evidence:33ac181ea5411f80f15906f644c74de347614209d73b33e280e412d2970628d4",
                    "evidence:af51c25c0f5de49cce076d4851c699b81084a1e9455c67163d3c6ea122f467a1",
                ),
                CaseClaimStatus.UNRESOLVED,
            ),
            CaseClaim(
                "claim:x5000r-inline-table-bindings",
                "Exported inline route tables bind 123 of 199 static frontend selectors to executable MIPS addresses; 124 registration proofs are retained because getTelnetCfg appears twice, while setLanCfg binds table entry 0x0044aa2c to handler 0x004209b8.",
                (
                    "evidence:7b8f6bc1380ed52f3b870059b0d9fdf6e31d08c1d6668712397c34f8578f08b5",
                    "evidence:40f4546d6cd758973c602b975270fd34a65952eb0af3480684e4df9c1f1f9b75",
                    "evidence:aa8f5f7a8b5cad1c0f36a8e6f603f37bd27a49409b107efb9ad8b15dda37c4f5",
                    "evidence:6df24edc5d0e4dc1e08efb25e9551a410f8a56acd526181f30ddaa10e1755f88",
                    "coverage:x5000r-mips-dispatch-set-difference",
                ),
            ),
            CaseClaim(
                "claim:x5000r-setlancfg-prefix-value-flow",
                "The branch-free prefix of setLanCfg maps request parameters lanIp and lanNetmask through websGetVar into nvram_set keys lan_ipaddr and lan_netmask; analysis stops at the first conditional branch.",
                (
                    "evidence:65068ce79bc8a710cbe30d9614bdecf0007d3e7d1319432405bab218ff3c9b1d",
                    "evidence:1a7119907f1f9f7e8f1e803e58560217703364813025bc453d4fc11e55b4d59f",
                    "coverage:x5000r-setlancfg-handler-prefix",
                ),
            ),
            CaseClaim(
                "claim:x5000r-set-difference-attribution",
                "A bounded scan attributes the 76 frontend-only operations as 38 auxiliary-page consumers and 38 wrapper-only declarations, while the 14 native-only registrations contain three frontend-scope gaps, one cross-native suffix-token variant, and ten registrations without a frontend reference; these are evidence shapes and search hypotheses, not proof of runtime ownership or causality.",
                (
                    "evidence:48c0ae04fd6e114f4f6980da1bf7345aff258957469d8bee893a648e28dc9277",
                    "evidence:4c27b133facef90524fbb2f238c4927c5a5e854543265e1579204ba85f6d75cc",
                    "evidence:df7756729dbf120b10d0460438f7187623d6ce7314d8ce85a75a5a0b8ab5c6a4",
                    "coverage:x5000r-set-difference-attribution",
                ),
            ),
            CaseClaim(
                "claim:x5000r-expanded-frontend-scope",
                "Expanding the first-class frontend graph to kr.js, wan_ie.html, and advance/config.html recovers getWanIeCfg, setWanIeCfg, and setUploadSetting with distinct request architectures; the frontend inventory grows from 199 to 203 operations, all three prior scope gaps leave the Native-only set, and the residual difference becomes 77 frontend-only versus 11 native-only operations.",
                (
                    "evidence:01b3a330fa09b9fa1f6951ebc6265bb37196e6384a33f1e64534fb69e3c4112a",
                    "evidence:e312a99e46a58c2daafe389faa164f3d5b4008f1eea34287ddbe66aaaa642177",
                    "evidence:83bcc17baff831a4f286d1b5286147e068adc965ecf0ba3228ddbee89dc1c0d3",
                    "evidence:2840a161f73b3015b5e8393dbc88179d70e6439929224f5d900ed45838a409d0",
                    "coverage:x5000r-expanded-frontend-scope",
                ),
            ),
            CaseClaim(
                "claim:x5000r-nested-upload-dispatch",
                "The MIPS CGI main dispatcher recognizes action=upload, extracts the second ampersand-delimited query segment, parses the multipart body through cutUploadFile, carries the segment into JSON topicurl, normalizes the slash suffix to setUploadSetting, selects set_handle_t, and invokes the exact handler registered at 0x0044a124 -> 0x0042bf14.",
                (
                    "evidence:ec15c78cfd749e28153a6b617362e41c678d9009c128ae970b7a1ac0e1af741a",
                    "evidence:2840a161f73b3015b5e8393dbc88179d70e6439929224f5d900ed45838a409d0",
                    "evidence:469a1724198b6c62aa45d85858d7fa6e6d54d720a5010aba54aeff8a637bf53a",
                    "evidence:7ba281dfa74b05759b9f20d6a7b84f7abab5dc2f871aab44957b6ba018a5b74a",
                    "evidence:3d00d3f04153c618cfab025441c125a843bcc2517f50856df7ccbf35b1401bbd",
                    "evidence:784717b02a18e526c5a837d5c1302c169a3206d9ce6f91c9f2f38d8b1ff70376",
                    "evidence:e03704a5b65ab6cd2113068c5599edc41c799777778b8d7f2cc57a5d601d9ed6",
                    "evidence:266baa8d476660a993a4476f3dc5fa95ecfc29ca2eace7c8c517b77e992f0816",
                    "coverage:x5000r-nested-upload-dispatch",
                ),
            ),
            CaseClaim(
                "claim:x5000r-custom-auth-path-exclusion",
                "The vendor-modified lighttpd protects matching .asp/.html/.htm/config.dat/login CGI response paths through userloginAuth, checkLoginUser, SESSION_ID extraction, session-table lookup, and HTTP 302 denial, but /cgi-bin/cstecgi.cgi matches none of those path gates and therefore reaches the separately proved upload dispatcher outside this static guard scope.",
                (
                    "evidence:00078b1dcdbde38a6323e0458697834454e6c0df2d830be7c8d5b9ba7557dc4e",
                    "evidence:e4fd7ac52f78bbddfd1156c1a541216ba013ee05f3fc67a9ed10828ffe6a18ca",
                    "evidence:14672792d961e5f439a7cfb3ba0f1c440d91e52ddf77780781d2cd0e18871801",
                    "evidence:d42f0701efb9ebf7eac1112e34eb916408f873e785db5749caabd87b46d82a90",
                    "evidence:36cbf6aae3090fab8d7d27000a90dfb3aeeedea42d2e87ac36ab8d62ec3b6977",
                    "coverage:x5000r-request-protection",
                ),
            ),
            CaseClaim(
                "claim:x5000r-static-service-assembly",
                "The rc initialization chain calls init_router -> start_services_once -> start_httpd, whose bounded argv selects /usr/sbin/lighttpd with /lighttp/lighttpd.conf; that configuration exposes 80/8080, maps /www/, and binds /cgi-bin/ to the shipped www/cgi-bin/cstecgi.cgi artifact.",
                (
                    "evidence:14d3736dfba5d6076335e303471997dde64fe1be5a7ca45eaeb6d0da9186c612",
                    "evidence:745154952409e4487d62a5bd8a92df73875de038912cf3fc50bd76c7e57a6624",
                    "evidence:07a865c5f28c93dfe821511f0a161b700f3a86ddb3412ab59b3a17d24bf5e6b0",
                    "evidence:2ce5ca93095e4ad51bea5c915f181e8042af0a0b39b9a03f36db95e5c6567d64",
                    "evidence:37a6599d2de737e244b5c91fd0a9eafab8c149563efbe22f3e3dfe5142590b34",
                    "evidence:d2ee6f5d3565fddc127bb6fbc56e7e5524556595c565d05e1d5973d38b5a3341",
                    "evidence:126f5f64cbf2eb921b9629b995345840917a89be9aa73ef44f77b851b4bd9732",
                    "evidence:95e5a2899396a30ad920f39c2838dacef0dfc562d716c143141a0a696e8c490d",
                    "evidence:7760bcc17531bc3d677d9579937aba1b094cf828b4ba366a53e9131051d97d2d",
                    "evidence:99bb5ef14b289639b11eabcfaaa1adf982d25de686ab4a2772fb08edc4b4b063",
                    "evidence:9f9fb21c6f6d88407ddf0ada7511faccaeec40477e54ca9b26561f90284105cf",
                    "coverage:x5000r-service-assembly",
                ),
            ),
            CaseClaim(
                "claim:x5000r-potential-hidden-interfaces",
                "After completed frontend and set-difference coverage, ten cstecgi.cgi registrations retain exact native handlers but have no observed frontend or auxiliary-native reference; they are preserved as potential hidden interfaces with open runtime-cause obligations, not labeled as backdoors.",
                ("coverage:x5000r-potential-hidden-interfaces",),
            ),
        ),
        stages=(
            CaseStage(
                "stage:x5000r-frontend", 1,
                "Separate the physical CGI endpoint from its logical JSON selector.",
                ("claim:x5000r-shared-endpoint",),
            ),
            CaseStage(
                "stage:x5000r-web-native", 2,
                "Confirm CGI execution and prioritize the concrete MIPS binary without claiming a handler binding.",
                ("claim:x5000r-cgi-execution", "claim:x5000r-native-selector-presence"),
                creates_obligations=("obligation:x5000r-cross-resource-endpoint",),
            ),
            CaseStage(
                "stage:x5000r-cross-resource-resolution", 3,
                "Resolve the endpoint definition and wrapper consumption across separate frontend assets while preserving both source locations.",
                ("claim:x5000r-cross-resource-endpoint",),
                creates_obligations=("obligation:x5000r-selector-handler",),
                resolves_obligations=("obligation:x5000r-cross-resource-endpoint",),
            ),
            CaseStage(
                "stage:x5000r-open-native-boundary", 4,
                "Retain selector-to-native-handler and native value-flow recovery as explicit work.",
                ("claim:x5000r-native-handler-binding",),
            ),
            CaseStage(
                "stage:x5000r-inline-native-table", 5,
                "Use exported symbol sizes and the 64-byte inline route plus executable pointer layout to close a verified selector subset without hiding unmatched operations.",
                ("claim:x5000r-inline-table-bindings",),
                creates_obligations=("obligation:x5000r-setlancfg-prefix-value-flow",),
            ),
            CaseStage(
                "stage:x5000r-setlancfg-prefix-value-flow", 6,
                "Resolve GP/GOT calls and register provenance only through the first branch, proving two request-parameter to configuration-state mappings while preserving the branched suffix as unknown.",
                ("claim:x5000r-setlancfg-prefix-value-flow",),
                creates_obligations=(
                    "obligation:x5000r-branched-value-flow",
                    "obligation:x5000r-set-difference-shape",
                ),
                resolves_obligations=("obligation:x5000r-setlancfg-prefix-value-flow",),
            ),
            CaseStage(
                "stage:x5000r-set-difference-attribution", 7,
                "Classify both sides of the frontend/native difference with exact, bounded auxiliary evidence; keep suffix-token variants separate from exact matches and retain unresolved runtime causes.",
                ("claim:x5000r-set-difference-attribution",),
                creates_obligations=("obligation:x5000r-frontend-scope-expansion",),
                resolves_obligations=("obligation:x5000r-set-difference-shape",),
            ),
            CaseStage(
                "stage:x5000r-expanded-frontend-scope", 8,
                "Promote the two referenced pages and kr.request implementation into the analyzed graph, preserving explicit URL, inherited default URL, payload-variable, and multipart upload-selector evidence as different request architectures.",
                ("claim:x5000r-expanded-frontend-scope",),
                creates_obligations=("obligation:x5000r-upload-mode-owner",),
                resolves_obligations=("obligation:x5000r-frontend-scope-expansion",),
            ),
            CaseStage(
                "stage:x5000r-nested-upload-dispatch", 9,
                "Replay the bounded MIPS main control-flow from upload-mode recognition through selector extraction, multipart parsing, JSON topicurl construction, slash-suffix normalization, set_handle_t selection, and exact handler invocation.",
                ("claim:x5000r-nested-upload-dispatch",),
                creates_obligations=(
                    "obligation:x5000r-upload-runtime-reachability",
                    "obligation:x5000r-upload-auth-guard",
                ),
                resolves_obligations=("obligation:x5000r-upload-mode-owner",),
            ),
            CaseStage(
                "stage:x5000r-custom-auth-path-exclusion", 10,
                "Trace the custom lighttpd suffix gate into SESSION_ID validation and HTTP 302 enforcement, then compare its exact protected path set with the upload CGI path instead of inferring authentication from the presence of login functions.",
                ("claim:x5000r-custom-auth-path-exclusion",),
                creates_obligations=(
                    "obligation:x5000r-static-service-assembly",
                ),
                rejects_obligations=("obligation:x5000r-upload-auth-guard",),
            ),
            CaseStage(
                "stage:x5000r-static-service-assembly", 11,
                "Replay the init_router to service-group to start_httpd calls, recover the exact _eval argv vector, and resolve its server/config/CGI artifacts without treating static assembly as a live process observation.",
                ("claim:x5000r-static-service-assembly",),
                resolves_obligations=(
                    "obligation:x5000r-static-service-assembly",
                ),
            ),
            CaseStage(
                "stage:x5000r-potential-hidden-interface-index", 12,
                "Apply the completed-coverage gate to the residual native-only registrations and publish all ten as a cross-firmware-queryable uncertainty class without upgrading static absence into a runtime or security conclusion.",
                ("claim:x5000r-potential-hidden-interfaces",),
            ),
        ),
        obligations=(
            CaseObligation(
                "obligation:x5000r-cross-resource-endpoint",
                "Resolve globalConfig.cgiUrl from its defining asset into topicurl wrapper consumers.",
                "resolves_endpoint_binding", CaseObligationStatus.RESOLVED,
                (
                    "evidence:340a0168af128fbe29827a9d42f4c5b6687017ad1152d2ed166c46835f962d31",
                    "evidence:7fae6c104f1f2dfd69650f3c02b095bfe85bb7f3b25bdd6de54c16919c0e305a",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-selector-handler",
                "Bind or explain the residual 77 frontend-only operations after scope expansion; upload is a newly recovered outer selector and must not be forced into the inline topicurl tables.",
                "binds_handler", CaseObligationStatus.OPEN,
            ),
            CaseObligation(
                "obligation:x5000r-setlancfg-prefix-value-flow",
                "Recover request-parameter to state writes in the straight-line setLanCfg prefix.",
                "maps_parameter_to_state", CaseObligationStatus.RESOLVED,
                (
                    "evidence:65068ce79bc8a710cbe30d9614bdecf0007d3e7d1319432405bab218ff3c9b1d",
                    "evidence:1a7119907f1f9f7e8f1e803e58560217703364813025bc453d4fc11e55b4d59f",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-branched-value-flow",
                "Recover branch-dependent DHCP state writes and downstream commit/network/sensitive sinks without merging mutually exclusive paths.",
                "traces_branched_value_flow", CaseObligationStatus.OPEN,
            ),
            CaseObligation(
                "obligation:x5000r-set-difference-shape",
                "Attribute the observed 76 frontend-only and 14 native-only operations without converting string similarity into a handler binding.",
                "attributes_set_difference", CaseObligationStatus.RESOLVED,
                (
                    "evidence:48c0ae04fd6e114f4f6980da1bf7345aff258957469d8bee893a648e28dc9277",
                    "evidence:4c27b133facef90524fbb2f238c4927c5a5e854543265e1579204ba85f6d75cc",
                    "evidence:df7756729dbf120b10d0460438f7187623d6ce7314d8ce85a75a5a0b8ab5c6a4",
                    "coverage:x5000r-set-difference-attribution",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-frontend-scope-expansion",
                "Expand the first-class frontend asset graph to cover wan_ie.html and advance/config.html, then determine whether their three exact selectors change the dispatcher comparison.",
                "expands_frontend_scope", CaseObligationStatus.RESOLVED,
                (
                    "evidence:01b3a330fa09b9fa1f6951ebc6265bb37196e6384a33f1e64534fb69e3c4112a",
                    "evidence:e312a99e46a58c2daafe389faa164f3d5b4008f1eea34287ddbe66aaaa642177",
                    "evidence:83bcc17baff831a4f286d1b5286147e068adc965ecf0ba3228ddbee89dc1c0d3",
                    "evidence:2840a161f73b3015b5e8393dbc88179d70e6439929224f5d900ed45838a409d0",
                    "coverage:x5000r-expanded-frontend-scope",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-upload-mode-owner",
                "Determine which upload-mode dispatcher consumes action=upload before setUploadSetting reaches the inline native registration, without treating their URL adjacency as a direct call edge.",
                "binds_upload_mode", CaseObligationStatus.RESOLVED,
                (
                    "evidence:469a1724198b6c62aa45d85858d7fa6e6d54d720a5010aba54aeff8a637bf53a",
                    "evidence:7ba281dfa74b05759b9f20d6a7b84f7abab5dc2f871aab44957b6ba018a5b74a",
                    "evidence:3d00d3f04153c618cfab025441c125a843bcc2517f50856df7ccbf35b1401bbd",
                    "evidence:784717b02a18e526c5a837d5c1302c169a3206d9ce6f91c9f2f38d8b1ff70376",
                    "evidence:e03704a5b65ab6cd2113068c5599edc41c799777778b8d7f2cc57a5d601d9ed6",
                    "evidence:266baa8d476660a993a4476f3dc5fa95ecfc29ca2eace7c8c517b77e992f0816",
                    "coverage:x5000r-nested-upload-dispatch",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-upload-runtime-reachability",
                "Verify that the upload path is reachable in the deployed runtime configuration and request lifecycle.",
                "verifies_runtime_reachability", CaseObligationStatus.OPEN,
            ),
            CaseObligation(
                "obligation:x5000r-static-service-assembly",
                "Prove that the shipped initialization path selects the web server, configuration, CGI namespace, and request artifact.",
                "assembles_static_service", CaseObligationStatus.RESOLVED,
                (
                    "evidence:14d3736dfba5d6076335e303471997dde64fe1be5a7ca45eaeb6d0da9186c612",
                    "evidence:745154952409e4487d62a5bd8a92df73875de038912cf3fc50bd76c7e57a6624",
                    "evidence:07a865c5f28c93dfe821511f0a161b700f3a86ddb3412ab59b3a17d24bf5e6b0",
                    "evidence:2ce5ca93095e4ad51bea5c915f181e8042af0a0b39b9a03f36db95e5c6567d64",
                    "evidence:37a6599d2de737e244b5c91fd0a9eafab8c149563efbe22f3e3dfe5142590b34",
                    "evidence:d2ee6f5d3565fddc127bb6fbc56e7e5524556595c565d05e1d5973d38b5a3341",
                    "evidence:126f5f64cbf2eb921b9629b995345840917a89be9aa73ef44f77b851b4bd9732",
                    "evidence:95e5a2899396a30ad920f39c2838dacef0dfc562d716c143141a0a696e8c490d",
                    "evidence:7760bcc17531bc3d677d9579937aba1b094cf828b4ba366a53e9131051d97d2d",
                    "evidence:99bb5ef14b289639b11eabcfaaa1adf982d25de686ab4a2772fb08edc4b4b063",
                    "evidence:9f9fb21c6f6d88407ddf0ada7511faccaeec40477e54ca9b26561f90284105cf",
                    "coverage:x5000r-service-assembly",
                ),
            ),
            CaseObligation(
                "obligation:x5000r-upload-auth-guard",
                "Recover authentication and authorization guards applied before the upload-mode branch.",
                "maps_auth_guard", CaseObligationStatus.REJECTED,
                (
                    "evidence:00078b1dcdbde38a6323e0458697834454e6c0df2d830be7c8d5b9ba7557dc4e",
                    "evidence:e4fd7ac52f78bbddfd1156c1a541216ba013ee05f3fc67a9ed10828ffe6a18ca",
                    "evidence:14672792d961e5f439a7cfb3ba0f1c440d91e52ddf77780781d2cd0e18871801",
                    "evidence:d42f0701efb9ebf7eac1112e34eb916408f873e785db5749caabd87b46d82a90",
                    "evidence:36cbf6aae3090fab8d7d27000a90dfb3aeeedea42d2e87ac36ab8d62ec3b6977",
                    "coverage:x5000r-request-protection",
                ),
            ),
        ),
        counterfactuals=(
            "Path-only grouping would collapse many distinct operations into one CGI interface.",
            "Frontend-only analysis would not identify cstecgi.cgi as a MIPS deep-analysis target.",
            "A native string hit alone would incorrectly imply a proved selector-to-handler binding.",
            "A single-resource frontend pass would miss 199 wrapper operations whose endpoint is defined in another asset.",
            "Treating a selector string hit as a binding would hide the 76 frontend-only and 14 Native-only operation differences.",
            "Linear scanning past the first conditional branch could combine mutually exclusive DHCP paths into a false value-flow.",
            "Substring matching would misclassify loginAuth as an exact cross-native occurrence because usr/sbin/lighttpd contains userloginAuth; the suffix-token variant remains only a candidate clue.",
            "Analyzing only shared wrapper files would leave three implemented operations labeled Native-only; conversely, flattening the multipart URL would hide the distinct outer upload mode and inner setUploadSetting selector.",
            "Treating the setUploadSetting table entry alone as proof would miss the preceding action=upload branch, multipart parser, query-segment transfer, and slash normalization that make the handler reachable from this request shape.",
            "Finding SESSION_ID and checkLoginUser in lighttpd would falsely imply that every CGI request is protected; only branch-level comparison shows that the suffix gate excludes /cgi-bin/cstecgi.cgi.",
            "Finding a start_httpd function or lighttpd strings alone would not prove the service is part of the initialization chain or which configuration and CGI artifact it selects.",
        ),
        paper_uses=(
            "Motivating example for operation identity below a shared physical endpoint.",
            "Ablation of path-only, frontend-plus-config, and native-dispatch analysis.",
            "Evidence-preserving example of closing a cross-resource JavaScript obligation while retaining a native value-flow obligation.",
            "Frontend/native set-difference experiment for version drift, dead UI code, and alternate backend hypotheses.",
            "Instruction-level example showing why handler ownership alone is insufficient: concrete request fields must be followed into configuration state.",
            "Evidence-backed case study showing how frontend/native set differences expose incomplete asset scope, wrapper-only declarations, and native registrations without inventing backend equivalence.",
            "Scope-expansion example showing three request architectures behind one CGI: direct literal request, inherited kr.request default with payload-variable selector, and multipart upload URL with nested selectors.",
            "Instruction-level nested-dispatch example showing why a firmware map can identify the correct binary and handler where endpoint text or vulnerability prose cannot.",
            "Cross-binary protection-scope example showing why page authentication and CGI operation authorization must be mapped independently before reasoning about a vulnerability mechanism.",
            "Static service-assembly example separating boot-path configuration proof from live runtime observation.",
            "Coverage-gated hidden-interface candidate set for cross-firmware prevalence, handler clustering, and later runtime-resolution experiments.",
        ),
        limitations=(
            "The 199 operations are statically enumerated wrapper assignments; dynamically constructed selectors may still exist.",
            "Only the branch-free setLanCfg prefix is proven; DHCP branches, commits, network reconfiguration, and sensitive sinks remain open.",
            "CGI execution configuration does not prove runtime reachability or authentication state.",
            "The two setLanCfg mappings do not establish exploitability, runtime reachability, or dangerous sink access.",
            "Set-difference categories describe observed static evidence only; version drift, dead code, alternate processes, generated requests, and runtime registration still require separate proof.",
            "The deterministic Profile proves the static native control-flow edge from action=upload to setUploadSetting, but it does not prove runtime reachability, authentication state, or exploitability.",
            "The custom-auth Profile rejects a guard only within the shipped lighttpd response path and cstecgi dispatcher evidence; external proxies, runtime configuration changes, network policy, and exploitability remain outside this static claim.",
            "The service-assembly Profile proves the shipped initialization and configuration chain, not that a particular boot completed or that the process and listeners were observed live.",
            "A missing observed frontend reference does not distinguish a hidden client, direct API, dead code, version skew, or runtime-only registration without additional evidence.",
        ),
    ))


def build_ac9_dlna_fixture_split_case():
    """Preserve the unresolved split between UI contract and daemon architecture."""

    report = json.loads(AC9_R2_10_REPORT.read_text(encoding="utf-8"))
    relationship_report = json.loads(
        AC9_R2_11_REPORT.read_text(encoding="utf-8")
    )
    command_chain_report = json.loads(
        AC9_R2_12_REPORT.read_text(encoding="utf-8")
    )
    usb_status_report = json.loads(
        AC9_R2_13_REPORT.read_text(encoding="utf-8")
    )
    feature_gate_report = json.loads(
        AC9_R2_14_REPORT.read_text(encoding="utf-8")
    )
    usb_status_dlna_xref_ids = {
        item["xref_id"]
        for item in usb_status_report["usb_status_route_handler_chain"][
            "dlna_literal_xrefs"
        ]
    }
    atoms = (
        *report["dlna_response_fixture_evidence"],
        *report["dlna_architecture_evidence"],
        *relationship_report["dlna_relationship_evidence"],
        *command_chain_report["daemon_command_chain_evidence"],
        *usb_status_report["usb_status_route_handler_evidence"],
        *feature_gate_report["disabled_dlna_feature_chain"]["gate_evidence"],
        *feature_gate_report["disabled_dlna_feature_chain"]["request_evidence"],
    )
    selected = []
    selected_ids = set()
    for atom in atoms:
        source_path = atom["source_span"]["artifact_path"]
        capability = atom["capability"]
        producer = atom["producer"]
        is_dlna_frontend_request = (
            source_path == "webroot_ro/js/dlna.js"
            and capability == "constructs_request"
            and "expandDlnaFile" in atom["object_value"]
        )
        is_fixture_or_architecture = (
            source_path == "webroot_ro/goform/expandDlnaFile.txt"
            or capability in {
                "prepares_media_mount",
                "aliases_media_download",
                "reads_dlna_state",
                "monitors_media_daemon",
            }
        )
        is_selected_command_or_xref = (
            producer in {
                "native-symbol-command-table",
                "native-arm-literal-xref",
            }
            and (
                source_path != "bin/httpd"
                or atom["subject_ref"] in usb_status_dlna_xref_ids
            )
        )
        is_usb_status_binding = (
            producer == "native-deep-arm-pic-callsite"
            and atom["subject_ref"]
            == usb_status_report["usb_status_route_handler_chain"]["binding_id"]
        )
        is_usb_status_frontend = (
            producer == "frontend-request-producer"
            and atom["object_value"] == "goform/GetUSBStatus?"
        )
        is_feature_gate = producer == "frontend-feature-gate"
        is_disabled_dlna_request = (
            producer == "frontend-request-producer"
            and source_path == "webroot_ro/js/dlna.js"
        )
        if (
            is_dlna_frontend_request
            or is_fixture_or_architecture
            or producer == "native-embedded-command-relationship"
            or is_selected_command_or_xref
            or is_usb_status_binding
            or is_usb_status_frontend
            or is_feature_gate
            or is_disabled_dlna_request
        ):
            if atom["evidence_id"] not in selected_ids:
                selected.append(atom)
                selected_ids.add(atom["evidence_id"])
    atom_evidence = tuple(
        CaseEvidenceReference(
            atom["evidence_id"],
            (
                CaseEvidenceKind.FRONTEND_REQUEST
                if atom["producer"] == "frontend-request-producer"
                else CaseEvidenceKind.FRONTEND_FEATURE_GATE
                if atom["producer"] == "frontend-feature-gate"
                else CaseEvidenceKind.RESPONSE_FIXTURE
                if atom["producer"] == "response-fixture-producer"
                else CaseEvidenceKind.NATIVE_RELATIONSHIP
                if atom["producer"] == "native-embedded-command-relationship"
                else CaseEvidenceKind.NATIVE_COMMAND_BINDING
                if atom["producer"] == "native-symbol-command-table"
                else CaseEvidenceKind.NATIVE_LITERAL_XREF
                if atom["producer"] == "native-arm-literal-xref"
                else CaseEvidenceKind.NATIVE_BINDING
                if atom["producer"] == "native-deep-arm-pic-callsite"
                else CaseEvidenceKind.WEB_CONFIGURATION
                if atom["source_span"]["artifact_path"].startswith("etc_ro/")
                else CaseEvidenceKind.NATIVE_HINT
            ),
            atom["source_span"]["artifact_path"],
            atom["source_span"]["artifact_sha256"],
            atom["source_span"]["locator"],
            atom["capability"],
            "{}@{}".format(atom["producer"], atom["producer_version"]),
        )
        for atom in selected
    )
    target_resolution_ref = CaseEvidenceReference(
        "coverage:ac9-native-relationship-target-resolution",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_11_REPORT.as_posix(),
        hashlib.sha256(AC9_R2_11_REPORT.read_bytes()).hexdigest(),
        "json:$.dlna_relationships",
        "resolves_target_component_presence",
        "native-relationship-report@v1alpha1",
    )
    family_report_sha = hashlib.sha256(AC9_R2_15_REPORT.read_bytes()).hexdigest()
    ac9_feature_pivot_ref = CaseEvidenceReference(
        "coverage:ac9-dlna-feature-pivots",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_15_REPORT.as_posix(),
        family_report_sha,
        "json:$.ac9_primary.dlna_feature_pivots",
        "bounds_disabled_feature_native_pivots",
        "native-arm-feature-pivot@0.1.0",
    )
    ac18_positive_control_ref = CaseEvidenceReference(
        "coverage:ac18-dlna-route-positive-control",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_15_REPORT.as_posix(),
        family_report_sha,
        "json:$.ac18_positive_control.dlna_route_bindings",
        "proves_neighbor_variant_route_bindings",
        "native-deep-arm-pic-callsite@0.1.0",
    )
    family_equivalence_ref = CaseEvidenceReference(
        "coverage:ac9-ac18-dlna-family-equivalence",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_15_REPORT.as_posix(),
        family_report_sha,
        "json:$.family_comparison",
        "compares_family_variant_assets_and_feature_state",
        "family-variant-report@v1alpha1",
    )
    reachability_report_sha = hashlib.sha256(
        AC9_R2_16_REPORT.read_bytes()
    ).hexdigest()
    ac9_reachability_ref = CaseEvidenceReference(
        "coverage:ac9-dlna-frontend-reachability",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_16_REPORT.as_posix(),
        reachability_report_sha,
        "json:$.ac9_primary.dlna_operations",
        "classifies_frontend_invocation_reachability",
        "frontend-invocation-reachability@0.1.0",
    )
    ac18_reachability_ref = CaseEvidenceReference(
        "coverage:ac18-dlna-frontend-reachability-control",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_16_REPORT.as_posix(),
        reachability_report_sha,
        "json:$.ac18_positive_control.dlna_operations",
        "controls_frontend_invocation_reachability",
        "frontend-invocation-reachability@0.1.0",
    )
    graph_report_sha = hashlib.sha256(AC9_R2_17_REPORT.read_bytes()).hexdigest()
    ac9_graph_ref = CaseEvidenceReference(
        "coverage:ac9-dlna-communication-graph",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_17_REPORT.as_posix(), graph_report_sha,
        "json:$.ac9_primary.focused_graph",
        "projects_artifact_local_communication_architecture",
        "communication-architecture-graph@v1alpha1",
    )
    ac18_graph_ref = CaseEvidenceReference(
        "coverage:ac18-dlna-communication-graph-control",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_17_REPORT.as_posix(), graph_report_sha,
        "json:$.ac18_positive_control.focused_graph",
        "controls_artifact_local_route_handler_projection",
        "communication-architecture-graph@v1alpha1",
    )
    query_report_sha = hashlib.sha256(AC9_R2_18_REPORT.read_bytes()).hexdigest()
    ac9_graph_query_ref = CaseEvidenceReference(
        "coverage:ac9-dlna-persisted-graph-query",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_18_REPORT.as_posix(), query_report_sha,
        "json:$.queries",
        "replays_persisted_graph_queries_with_evidence",
        "communication-graph-query@v1alpha1",
    )
    product_graph_report_sha = hashlib.sha256(
        AC9_R2_19_REPORT.read_bytes()
    ).hexdigest()
    ac9_product_graph_ref = CaseEvidenceReference(
        "coverage:ac9-dlna-http-console-graph",
        CaseEvidenceKind.COVERAGE_LEDGER,
        AC9_R2_19_REPORT.as_posix(), product_graph_report_sha,
        "json:$.http_acceptance",
        "replays_product_graph_query_with_evidence",
        "communication-graph-http-console@v1alpha1",
    )
    evidence = (
        *atom_evidence,
        target_resolution_ref,
        ac9_feature_pivot_ref,
        ac18_positive_control_ref,
        family_equivalence_ref,
        ac9_reachability_ref,
        ac18_reachability_ref,
        ac9_graph_ref,
        ac18_graph_ref,
        ac9_graph_query_ref,
        ac9_product_graph_ref,
    )
    by_capability = {}
    for item in evidence:
        by_capability.setdefault(item.capability, []).append(item.evidence_ref)
    frontend_refs = tuple(
        item.evidence_ref for item in evidence
        if (
            item.kind is CaseEvidenceKind.FRONTEND_REQUEST
            and item.source_path == "webroot_ro/js/dlna.js"
        )
    )
    feature_gate_refs = tuple(
        item.evidence_ref for item in evidence
        if item.kind is CaseEvidenceKind.FRONTEND_FEATURE_GATE
    )
    fixture_refs = tuple(
        item.evidence_ref for item in evidence
        if item.kind is CaseEvidenceKind.RESPONSE_FIXTURE
    )
    architecture_refs = tuple(
        item.evidence_ref for item in evidence
        if item.capability in {
            "prepares_media_mount",
            "aliases_media_download",
            "reads_dlna_state",
            "monitors_media_daemon",
        }
    )
    relationship_refs = tuple(
        item.evidence_ref for item in evidence
        if item.kind is CaseEvidenceKind.NATIVE_RELATIONSHIP
    )
    target_resolution_refs = (target_resolution_ref.evidence_ref,)
    command_binding_refs = tuple(
        item.evidence_ref for item in evidence
        if item.kind is CaseEvidenceKind.NATIVE_COMMAND_BINDING
    )
    literal_xref_refs = tuple(
        item.evidence_ref for item in evidence
        if (
            item.kind is CaseEvidenceKind.NATIVE_LITERAL_XREF
            and item.source_path == "bin/time_check"
        )
    )
    usb_status_frontend_refs = tuple(
        item.evidence_ref for item in evidence
        if (
            item.kind is CaseEvidenceKind.FRONTEND_REQUEST
            and item.source_path == "webroot_ro/js/main.js"
        )
    )
    usb_status_binding_refs = tuple(
        item.evidence_ref for item in evidence
        if item.kind is CaseEvidenceKind.NATIVE_BINDING
    )
    usb_status_literal_xref_refs = tuple(
        item.evidence_ref for item in evidence
        if (
            item.kind is CaseEvidenceKind.NATIVE_LITERAL_XREF
            and item.source_path == "bin/httpd"
        )
    )
    return build_research_case(ResearchCaseInput(
        case_key="tenda-ac9-dlna-fixture-daemon-split",
        title="Tenda AC9: DLNA response fixtures without a proven goform handler",
        firmware_artifact_sha256=AC9_FIRMWARE_SHA256,
        architecture_tags=(
            "frontend_response_fixture",
            "unresolved_goform_binding",
            "minidlna_supervisor",
            "usb_media_mount",
            "embedded_process_ipc_relationships",
            "missing_target_component",
            "symbol_profiled_command_table",
            "arm_pic_literal_xref",
            "tail_merged_route_registration",
            "frontend_tokenizer_coverage_repair",
            "disabled_frontend_feature_gate",
            "residual_ui_request",
            "bounded_feature_literal_pivot",
            "family_variant_positive_control",
            "frontend_static_invocation_reachability",
        ),
        research_question=(
            "Do bundled DLNA request code and JSON response fixtures prove that "
            "the analyzed firmware registers the corresponding goform handlers, "
            "and is the declared UI path enabled in this product build?"
        ),
        evidence=evidence,
        claims=(
            CaseClaim(
                "claim:dlna-frontend-request",
                "The DLNA page script constructs GetDlnaCfg, SetDlnaCfg, "
                "refreshDLNA, and expandDlnaFile requests.",
                frontend_refs,
            ),
            CaseClaim(
                "claim:dlna-feature-disabled-ui-path",
                "CONFIG_DLNA_SERVER is n while the UI reveal predicate requires y; "
                "the exact feature-map, route, page, and same-stem script chain "
                "therefore classifies all four bundled DLNA requests as residual "
                "requests behind a disabled declared UI path.",
                (*feature_gate_refs, *frontend_refs),
            ),
            CaseClaim(
                "claim:dlna-response-contract",
                "A bundled JSON fixture declares the expandDlnaFile response shape.",
                fixture_refs,
            ),
            CaseClaim(
                "claim:dlna-daemon-architecture",
                "Independent static evidence establishes media mount preparation, "
                "nginx download aliasing, httpd DLNA state text, and minidlna monitoring.",
                architecture_refs,
            ),
            CaseClaim(
                "claim:dlna-native-relationships",
                "Embedded commands establish httpd signaling minidlna and "
                "time_check posting literal topic 51 operation 6 to netctrl; "
                "the minidlna target artifact is absent from this rootfs.",
                (*relationship_refs, *target_resolution_refs),
            ),
            CaseClaim(
                "claim:dlna-supervision-command-handler",
                "The daemon_exe_info record binds minidlna and literal topic 51 "
                "operation 6 to handler 0x15868; that handler references the media "
                "mount and time_check_daemon_minidlna literals.",
                (*command_binding_refs, *literal_xref_refs),
            ),
            CaseClaim(
                "claim:dlna-usb-status-route-handler",
                "main.js constructs GetUSBStatus; a tail-merged ARM registration "
                "binds that route to formGetUSBStatus@0xa62d0, whose exact function "
                "references dlna.en, /var/etc/upan, and dlna literals.",
                (
                    *usb_status_frontend_refs,
                    *usb_status_binding_refs,
                    *usb_status_literal_xref_refs,
                ),
            ),
            CaseClaim(
                "claim:dlna-family-variant-positive-control",
                "The AC9 build has only three bounded DLNA literal pivots, all "
                "inside the verified GetUSBStatus handler, while an independently "
                "analyzed official AC18 enabled build registers GetDlnaCfg, "
                "SetDlnaCfg, and expandDlnaFile; byte-equivalent fixtures and a "
                "normalized-equivalent page asset support a shared family-template "
                "and build-pruning candidate without transferring ownership to AC9.",
                (
                    ac9_feature_pivot_ref.evidence_ref,
                    ac18_positive_control_ref.evidence_ref,
                    family_equivalence_ref.evidence_ref,
                ),
            ),
            CaseClaim(
                "claim:dlna-frontend-invocation-reachability",
                "In both AC9 and the AC18 control, GetDlnaCfg and SetDlnaCfg "
                "are top-level declarations, expandDlnaFile has a bounded "
                "initEvent-to-getMoreFolder call path, and refreshDLNA is "
                "declared but unreached with a commented binding. These are "
                "static invocation classes, not runtime execution claims.",
                (
                    ac9_reachability_ref.evidence_ref,
                    ac18_reachability_ref.evidence_ref,
                ),
            ),
            CaseClaim(
                "claim:dlna-communication-graph-projection",
                "One Catalog-only graph projection preserves AC9's four open "
                "DLNA route-owner obligations while independently connecting "
                "three AC18 operations to evidence-backed handlers; refreshDLNA "
                "remains ownerless in both artifacts.",
                (ac9_graph_ref.evidence_ref, ac18_graph_ref.evidence_ref),
            ),
            CaseClaim(
                "claim:dlna-persisted-graph-query",
                "The completed AC9 graph survives immutable SQLite publication "
                "and repository reopen, then yields bounded interface, parameter, "
                "completeness, minidlna-component, and dlnaEn-evidence queries "
                "without changing the four open Web owner obligations.",
                (ac9_graph_query_ref.evidence_ref,),
            ),
            CaseClaim(
                "claim:dlna-product-graph-query",
                "The product HTTP adapter and Console recover the same four "
                "AC9 DLNA interfaces, parameter evidence, and four open owner "
                "obligations through the shared persisted-query interface; "
                "the presentation layer does not infer a handler.",
                (ac9_product_graph_ref.evidence_ref,),
            ),
            CaseClaim(
                "claim:dlna-handler-owner",
                "In the AC9 artifact, no exact Native registration or handler binding connects "
                "GetDlnaCfg, SetDlnaCfg, refreshDLNA, or expandDlnaFile to a goform "
                "execution path; the adjacent GetUSBStatus binding does not establish "
                "an alias for those operations.",
                (
                    *frontend_refs, *feature_gate_refs,
                    *fixture_refs, *architecture_refs,
                    *relationship_refs, *target_resolution_refs,
                    *command_binding_refs, *literal_xref_refs,
                    *usb_status_frontend_refs, *usb_status_binding_refs,
                    *usb_status_literal_xref_refs,
                    ac9_feature_pivot_ref.evidence_ref,
                    ac18_positive_control_ref.evidence_ref,
                    family_equivalence_ref.evidence_ref,
                    ac9_reachability_ref.evidence_ref,
                    ac18_reachability_ref.evidence_ref,
                    ac9_graph_ref.evidence_ref,
                    ac18_graph_ref.evidence_ref,
                    ac9_graph_query_ref.evidence_ref,
                    ac9_product_graph_ref.evidence_ref,
                ),
                CaseClaimStatus.UNRESOLVED,
            ),
        ),
        stages=(
            CaseStage(
                "stage:dlna-frontend", 1,
                "Recover the request while leaving backend ownership open.",
                ("claim:dlna-frontend-request",),
                creates_obligations=("obligation:dlna-handler-owner",),
            ),
            CaseStage(
                "stage:dlna-response-fixture", 2,
                "Recover response fields as fixture-declared clues, not runtime facts.",
                ("claim:dlna-response-contract",),
            ),
            CaseStage(
                "stage:dlna-daemon-architecture", 3,
                "Recover the independent media mount and daemon supervision branch.",
                ("claim:dlna-daemon-architecture", "claim:dlna-handler-owner"),
            ),
            CaseStage(
                "stage:dlna-native-relationships", 4,
                "Recover embedded process/IPC edges and verify target presence "
                "without promoting them to executed callsites.",
                ("claim:dlna-native-relationships", "claim:dlna-handler-owner"),
                creates_obligations=("obligation:dlna-supervisor-ipc-binding",),
            ),
            CaseStage(
                "stage:dlna-command-handler-xref", 5,
                "Resolve the daemon command-table callback and prove literals "
                "referenced by that exact ARM function.",
                (
                    "claim:dlna-supervision-command-handler",
                    "claim:dlna-handler-owner",
                ),
                resolves_obligations=("obligation:dlna-supervisor-ipc-binding",),
            ),
            CaseStage(
                "stage:dlna-usb-status-route-handler", 6,
                "Repair regex-aware frontend tokenization, replay the nonlocal "
                "tail-merged ARM registration, and deepen only that verified "
                "handler to function-scoped literal xrefs without treating it as "
                "an alias for the still-unbound DLNA operations.",
                (
                    "claim:dlna-usb-status-route-handler",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-disabled-feature-gate", 7,
                "Follow the exact macro-to-menu-to-page-to-script chain and "
                "classify the four frontend-only operations as residual requests "
                "without converting UI disablement into backend absence.",
                (
                    "claim:dlna-feature-disabled-ui-path",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-family-variant-positive-control", 8,
                "Pivot from the exact disabled feature token into registered AC9 "
                "handlers, then compare an official independently mapped AC18 "
                "enabled build while preserving artifact-local ownership.",
                (
                    "claim:dlna-family-variant-positive-control",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-frontend-invocation-reachability", 9,
                "Classify each frontend request declaration against bounded "
                "static call roots while preserving runtime uncertainty.",
                (
                    "claim:dlna-frontend-invocation-reachability",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-communication-graph-projection", 10,
                "Project artifact-local interface, parameter, invocation, route, "
                "handler, coverage, and obligation facts; then close only stale "
                "obligations covered by exact supported deep bindings.",
                (
                    "claim:dlna-communication-graph-projection",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-persisted-graph-query", 11,
                "Publish the complete artifact-local graph with its source "
                "Catalog, reopen storage, and replay bounded UI/query views "
                "while preserving evidence and unresolved ownership.",
                (
                    "claim:dlna-persisted-graph-query",
                    "claim:dlna-handler-owner",
                ),
            ),
            CaseStage(
                "stage:dlna-product-graph-query", 12,
                "Replay the persisted graph through the real HTTP adapter and "
                "Console interface focus, presets, and EvidenceAtom panel "
                "without adding presentation-layer inference.",
                (
                    "claim:dlna-product-graph-query",
                    "claim:dlna-handler-owner",
                ),
            ),
        ),
        obligations=(
            CaseObligation(
                "obligation:dlna-handler-owner",
                "Locate or reject a route registration and handler for the DLNA goform operations.",
                "binds_handler",
                CaseObligationStatus.OPEN,
            ),
            CaseObligation(
                "obligation:dlna-supervisor-ipc-binding",
                "Bind the minidlna supervisor state path to its exact IPC command handler.",
                "binds_command_handler",
                CaseObligationStatus.RESOLVED,
                (*command_binding_refs, *literal_xref_refs),
            ),
        ),
        counterfactuals=(
            "Treating a response fixture filename as a route table would invent a handler binding.",
            "Treating minidlna monitoring as proof that httpd implements every DLNA UI operation would merge separate process roles.",
            "Discarding the fixture because Native route text is absent would lose recoverable response-field contracts.",
            "Treating an embedded command as an executed callsite would conceal the absent minidlna target component.",
            "Using data-layout proximity without the dynamic symbol, executable callback pointer, and code xrefs would not prove a handler chain.",
            "Treating GetUSBStatus as an alias for four differently named DLNA operations would turn shared state access into a fabricated route binding.",
            "Treating CONFIG_DLNA_SERVER=n alone as proof would miss whether the symbol actually gates this menu target, page, script, and request set.",
            "Transferring AC18 handler addresses or vulnerability state to AC9 would confuse a family-level positive control with artifact-local proof.",
            "Treating declared-but-unreached as dead code or runtime inaccessibility would overstate a bounded static call-graph result.",
            "Hiding a stale open obligation after deeper binding evidence arrives would make the graph contradict its own evidence timeline.",
            "Reimplementing graph traversal in each UI would allow view filters to become an unreviewed second inference engine.",
            "Rendering a full unbounded graph in the browser would hide query budgets, mix unrelated interfaces, and make visual proximity look evidentiary.",
        ),
        paper_uses=(
            "Negative case showing that interface-contract evidence and execution ownership are distinct layers.",
            "Coverage-preservation example where deeper evidence enriches architecture but keeps the central obligation open.",
            "Ablation for frontend-only, fixture-aware, and daemon-architecture-aware mapping.",
            "Missing-component example where an exact process target is named but absent from the analyzed rootfs.",
            "Temporal obligation example where a deeper adapter closes the supervision chain while the Web handler remains open.",
            "Compiler-layout case where a shared registrar tail hides one frontend-observed route from a contiguous callsite scanner.",
            "Product-variant case showing how an exact disabled-feature chain explains residual frontend-only operations while preserving the backend-ownership obligation.",
            "Family holdout showing that enabled variants can prioritize symbols and structures without resolving a disabled target build by analogy.",
            "Frontend reachability ablation separating request declaration, bounded active paths, and commented or unreached functions.",
            "Graph-projection case showing artifact-local owner separation and a late-evidence obligation state transition.",
            "Persistence/query case showing that reproducible analyst views can preserve the same evidence and open obligations across process restarts.",
            "Product-adapter case showing that HTTP and interactive graph views can share one evidence-preserving query semantics.",
        ),
        limitations=(
            "Static absence cannot distinguish dead UI, version skew, hashed dispatch, generated registration, or a missing conditional component.",
            "The fixture may be development data and does not establish runtime response values.",
            "No runtime boot, request replay, authentication, vulnerability, or exploitability claim is made.",
            "The proven supervision callback is not tied to any DLNA goform route registration or Web request handler.",
            "The proven static callback chain does not show that the callback or its embedded command executed at runtime.",
            "The GetUSBStatus handler proves an adjacent dashboard status path, not ownership or aliasing of the separate DLNA configuration operations.",
            "A disabled declared UI path does not prove backend absence, runtime inaccessibility, or behavior in another product/version build.",
            "The AC18 positive control proves only AC18 bindings; the AC9 benchmark remains a repacked rootfs and may omit partitions or conditional components.",
            "The v1 frontend call graph is intrafile and bounded; dynamic property calls, cross-resource wiring, and runtime event eligibility remain open.",
        ),
    ))


def build_research_case_corpus() -> dict:
    cases = (
        build_ac9_split_web_stack_case(),
        build_x5000r_shared_cgi_case(),
        build_ac9_dlna_fixture_split_case(),
    )
    validation = validate_research_case_corpus(cases)
    return {
        "schema_version": "firmatlas.mapping.research-case-corpus/v1alpha1",
        "cases": [case.to_dict() for case in cases],
        "validation": validation.to_dict(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(
        build_research_case_corpus(), ensure_ascii=False, indent=2
    ) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
