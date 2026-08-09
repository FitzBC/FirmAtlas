#!/usr/bin/env python3
"""Build deterministic, paper-oriented communication-mapping case records."""

from __future__ import annotations

import json

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


def build_ac9_split_web_stack_case():
    """Preserve the evidence progression from namespace gap to native binding."""

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
                "evidence:be1603c27afb7608e60987579f894ee5cb8c460298935038f8adade2fdfb7c01",
                CaseEvidenceKind.FRONTEND_REQUEST,
                "webroot_ro/js/online_list.js",
                "dd06a5b73cfd64686e5faaf497784190ac5b06801d9f6beb3fb8d90b7bf5cf87",
                "text_utf8:bytes=8902-8925;lines=293:10-293:33",
                "constructs_request",
                "frontend-request-producer@0.2.0",
            ),
            CaseEvidenceReference(
                "evidence:b4e7db7994cd77bf793b56bdd8fe094b1a7bd597c506c75b5c0d96d0a444ed81",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=703-707;lines=36:22-36:26",
                "listens_on",
                "web-configuration-producer@0.3.0",
            ),
            CaseEvidenceReference(
                "evidence:3b6cfac5872906fd9400e03ffe6d4a76576f2f3a8455b6f9a2e9f7269bf592f4",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=971-985;lines=49:17-49:31",
                "maps_namespace",
                "web-configuration-producer@0.3.0",
            ),
            CaseEvidenceReference(
                "evidence:cfc1150db9836df69bc7bb7a2ebbd4b7bcc6219993a88b00c59f20142fb6dd30",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx_init.sh",
                "c1e33c019efab0ac120c99c0abf8b66bbbdb6b64ba2ea855abcace257195b9a1",
                "text_utf8:bytes=114-138;lines=6:33-6:57",
                "starts",
                "web-configuration-producer@0.3.0",
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
                ("evidence:be1603c27afb7608e60987579f894ee5cb8c460298935038f8adade2fdfb7c01",),
            ),
            CaseClaim(
                "claim:fastcgi-branch",
                "A distinct nginx branch listens on :8180 and forwards "
                "/cgi-bin/luci/ to 127.0.0.1:8188, where app_data_center is started.",
                (
                    "evidence:b4e7db7994cd77bf793b56bdd8fe094b1a7bd597c506c75b5c0d96d0a444ed81",
                    "evidence:3b6cfac5872906fd9400e03ffe6d4a76576f2f3a8455b6f9a2e9f7269bf592f4",
                    "evidence:cfc1150db9836df69bc7bb7a2ebbd4b7bcc6219993a88b00c59f20142fb6dd30",
                ),
            ),
            CaseClaim(
                "claim:namespace-divergence",
                "The observed nginx namespaces do not establish ownership of "
                "/goform; backend ownership must remain unresolved at this stage.",
                (
                    "evidence:be1603c27afb7608e60987579f894ee5cb8c460298935038f8adade2fdfb7c01",
                    "evidence:3b6cfac5872906fd9400e03ffe6d4a76576f2f3a8455b6f9a2e9f7269bf592f4",
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
        ),
        counterfactuals=(
            "A firmware-level or path-style merge would incorrectly assign /goform "
            "to the observed nginx/FastCGI namespace.",
            "Choosing dhttpd by filename alone would spend deep-analysis effort on "
            "the weaker candidate.",
            "Treating a route string and a similar symbol name as a binding would "
            "skip the registrar call-site proof.",
        ),
        paper_uses=(
            "Motivating case for why communication mapping must precede "
            "target-binary vulnerability analysis.",
            "Ablation case comparing frontend-only, configuration-only, "
            "shallow-native, and full evidence fusion.",
            "Worked example for obligation-preserving analysis and false-merge prevention.",
        ),
        limitations=(
            "The native result proves selected static registrations, not runtime "
            "reachability or authentication state.",
            "The dhttpd negative control is bounded by the declared shallow producer "
            "and is not proof of total runtime non-participation.",
            "One firmware case motivates and illustrates the method but cannot "
            "establish cross-vendor generality.",
        ),
    ))


def build_x5000r_shared_cgi_case():
    """Preserve a shared physical CGI with a still-open native-dispatch proof."""

    return build_research_case(ResearchCaseInput(
        case_key="totolink-x5000r-shared-cgi-selector-dispatch",
        title="TOTOLINK X5000R: one CGI endpoint, multiple logical operations",
        firmware_artifact_sha256=X5000R_FIRMWARE_SHA256,
        architecture_tags=(
            "lighttpd_cgi", "shared_cgi_dispatcher", "json_topicurl_selector",
            "hybrid_query_and_json_dispatch",
        ),
        research_question=(
            "How can operations sharing /cgi-bin/cstecgi.cgi be kept distinct, "
            "and which native dispatch structure implements each selector?"
        ),
        evidence=(
            CaseEvidenceReference(
                "evidence:e84594b32b7f72f69bc268790212d8612a1c84bff9b43e11e1c0b514947fa5a9",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/config_ie.js",
                "6147395422cc29a9d77628450603d08f58fb8ed8b8b7916701e2eecf41183f0e",
                "text_utf8:bytes=1382-1402;lines=1:1277-1:1297",
                "constructs_request", "frontend-request-producer@0.2.0",
            ),
            CaseEvidenceReference(
                "evidence:0bb8be665021bced43b08b040bbca9a94f3f1440c1f3718df1628827ab4c9954",
                CaseEvidenceKind.FRONTEND_REQUEST, "www/static/js/config_ie.js",
                "6147395422cc29a9d77628450603d08f58fb8ed8b8b7916701e2eecf41183f0e",
                "text_utf8:bytes=1429-1439;lines=1:1324-1:1334",
                "selects_operation", "frontend-request-producer@0.2.0",
            ),
            CaseEvidenceReference(
                "evidence:948bf3c98411d5eda32ae8e148a056bd12db6f9f91c0ad9903b8d9865bf6f30c",
                CaseEvidenceKind.WEB_CONFIGURATION, "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=5556-5560;lines=147:31-147:35",
                "listens_on", "web-configuration-producer@0.3.0",
            ),
            CaseEvidenceReference(
                "evidence:51b716822d8f5eaa179e02f44ffe6d99d690b19fac712047238919c9f8cbe317",
                CaseEvidenceKind.WEB_CONFIGURATION, "lighttp/lighttpd.conf",
                "18916e824942442c1f9da7ead9916bf62257bcbd44797eca6c153341078e97e6",
                "text_utf8:bytes=8344-8354;lines=238:2-238:12",
                "binds_handler", "web-configuration-producer@0.3.0",
            ),
            CaseEvidenceReference(
                "evidence:af51c25c0f5de49cce076d4851c699b81084a1e9455c67163d3c6ea122f467a1",
                CaseEvidenceKind.NATIVE_HINT, "www/cgi-bin/cstecgi.cgi",
                "cb2aeef6f8a7a944e907181102cd240472f04c3c6857c2fd894a0d50ba347b93",
                "binary:bytes=233632-233642", "mentions_endpoint",
                "native-shallow-producer@0.1.0",
            ),
            CaseEvidenceReference(
                "coverage:topicurl-cross-resource-binding-open",
                CaseEvidenceKind.COVERAGE_LEDGER, "www/static/js/topicurl.js",
                "2170e9339adf4c3579ba015f19105c2ec03d1695796881589b0c5b163e059366",
                "coverage:complete-single-source;cross_resource_symbol=globalConfig.cgiUrl",
                "bounds_candidate_search", "frontend-request-producer@0.2.0",
            ),
        ),
        claims=(
            CaseClaim(
                "claim:x5000r-shared-endpoint",
                "The frontend posts JSON operation getInitCfg to /cgi-bin/cstecgi.cgi.",
                (
                    "evidence:e84594b32b7f72f69bc268790212d8612a1c84bff9b43e11e1c0b514947fa5a9",
                    "evidence:0bb8be665021bced43b08b040bbca9a94f3f1440c1f3718df1628827ab4c9954",
                ),
            ),
            CaseClaim(
                "claim:x5000r-cgi-execution",
                "lighttpd listens on 8080 and enables CGI execution for /cgi-bin/.",
                (
                    "evidence:948bf3c98411d5eda32ae8e148a056bd12db6f9f91c0ad9903b8d9865bf6f30c",
                    "evidence:51b716822d8f5eaa179e02f44ffe6d99d690b19fac712047238919c9f8cbe317",
                ),
            ),
            CaseClaim(
                "claim:x5000r-native-selector-presence",
                "The MIPS cstecgi.cgi binary contains the getInitCfg selector.",
                ("evidence:af51c25c0f5de49cce076d4851c699b81084a1e9455c67163d3c6ea122f467a1",),
            ),
            CaseClaim(
                "claim:x5000r-complete-operation-surface",
                "The cross-file wrapper operation surface and selector-to-native-handler bindings remain unresolved.",
                ("coverage:topicurl-cross-resource-binding-open",),
                CaseClaimStatus.UNRESOLVED,
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
                creates_obligations=("obligation:x5000r-selector-handler",),
            ),
            CaseStage(
                "stage:x5000r-open-boundary", 3,
                "Retain cross-resource symbol resolution and native dispatch recovery as explicit work.",
                ("claim:x5000r-complete-operation-surface",),
            ),
        ),
        obligations=(
            CaseObligation(
                "obligation:x5000r-selector-handler",
                "Resolve globalConfig.cgiUrl across assets and bind each topicurl selector to native dispatch code.",
                "binds_handler", CaseObligationStatus.OPEN,
            ),
        ),
        counterfactuals=(
            "Path-only grouping would collapse many distinct operations into one CGI interface.",
            "Frontend-only analysis would not identify cstecgi.cgi as a MIPS deep-analysis target.",
            "A native string hit alone would incorrectly imply a proved selector-to-handler binding.",
        ),
        paper_uses=(
            "Motivating example for operation identity below a shared physical endpoint.",
            "Ablation of path-only, frontend-plus-config, and native-dispatch analysis.",
            "Open-obligation case for cross-resource JavaScript and native value-flow recovery.",
        ),
        limitations=(
            "Current evidence proves selected operation presence, not the complete operation surface.",
            "CGI execution configuration does not prove runtime reachability or authentication state.",
            "Native selector strings do not yet identify handler functions or dangerous data flow.",
        ),
    ))


def build_research_case_corpus() -> dict:
    cases = (build_ac9_split_web_stack_case(), build_x5000r_shared_cgi_case())
    validation = validate_research_case_corpus(cases)
    return {
        "schema_version": "firmatlas.mapping.research-case-corpus/v1alpha1",
        "cases": [case.to_dict() for case in cases],
        "validation": validation.to_dict(),
    }


def main() -> int:
    print(json.dumps(build_research_case_corpus(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
