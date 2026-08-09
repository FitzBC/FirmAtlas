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
                "evidence:cf210fc7d542aeaf112b737083c5e0e28f1a62ba3c9379ca8b8a1b7633e0f296",
                CaseEvidenceKind.FRONTEND_REQUEST,
                "webroot_ro/js/online_list.js",
                "dd06a5b73cfd64686e5faaf497784190ac5b06801d9f6beb3fb8d90b7bf5cf87",
                "text_utf8:bytes=8902-8925;lines=293:10-293:33",
                "constructs_request",
                "frontend-request-producer@0.1.0",
            ),
            CaseEvidenceReference(
                "evidence:fbce8d64775c7863eec568b2e8ef4cab7ef00861fdbcb4da8fa62f9ba381cb04",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=703-707;lines=36:22-36:26",
                "listens_on",
                "web-configuration-producer@0.2.0",
            ),
            CaseEvidenceReference(
                "evidence:3d36e23710d1c0b10c3678592fdeb9dde9f34f3b88e18ea5f7f14ba44d865884",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx.conf",
                "66d18e21c0224ae7f738f8b97a7d4bc699669cd695e8f0432b7f8d3f54ac3663",
                "text_utf8:bytes=971-985;lines=49:17-49:31",
                "maps_namespace",
                "web-configuration-producer@0.2.0",
            ),
            CaseEvidenceReference(
                "evidence:b20a69d0c5ad8b2aebeca64c6855bd84c598d2e8fb57f7f6fc5e52ce13c7672c",
                CaseEvidenceKind.WEB_CONFIGURATION,
                "etc_ro/nginx/conf/nginx_init.sh",
                "c1e33c019efab0ac120c99c0abf8b66bbbdb6b64ba2ea855abcace257195b9a1",
                "text_utf8:bytes=114-138;lines=6:33-6:57",
                "starts",
                "web-configuration-producer@0.2.0",
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
                ("evidence:cf210fc7d542aeaf112b737083c5e0e28f1a62ba3c9379ca8b8a1b7633e0f296",),
            ),
            CaseClaim(
                "claim:fastcgi-branch",
                "A distinct nginx branch listens on :8180 and forwards "
                "/cgi-bin/luci/ to 127.0.0.1:8188, where app_data_center is started.",
                (
                    "evidence:fbce8d64775c7863eec568b2e8ef4cab7ef00861fdbcb4da8fa62f9ba381cb04",
                    "evidence:3d36e23710d1c0b10c3678592fdeb9dde9f34f3b88e18ea5f7f14ba44d865884",
                    "evidence:b20a69d0c5ad8b2aebeca64c6855bd84c598d2e8fb57f7f6fc5e52ce13c7672c",
                ),
            ),
            CaseClaim(
                "claim:namespace-divergence",
                "The observed nginx namespaces do not establish ownership of "
                "/goform; backend ownership must remain unresolved at this stage.",
                (
                    "evidence:cf210fc7d542aeaf112b737083c5e0e28f1a62ba3c9379ca8b8a1b7633e0f296",
                    "evidence:3d36e23710d1c0b10c3678592fdeb9dde9f34f3b88e18ea5f7f14ba44d865884",
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


def build_research_case_corpus() -> dict:
    cases = (build_ac9_split_web_stack_case(),)
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
