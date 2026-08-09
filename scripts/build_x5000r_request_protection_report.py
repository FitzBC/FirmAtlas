#!/usr/bin/env python3
"""Replay X5000R's custom lighttpd session gate against its upload CGI path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    MipsRequestProtectionAnchor,
    SourceArtifactEntry,
    discover_mips_request_protection,
)

if __package__:
    from scripts.build_x5000r_nested_dispatch_report import (
        X5000R_ROOT,
        build_analysis as build_nested_analysis,
    )
else:
    from build_x5000r_nested_dispatch_report import (
        X5000R_ROOT,
        build_analysis as build_nested_analysis,
    )


SERVER_PATH = "usr/sbin/lighttpd"
PROTECTED_PAGE = "/advance/config.html"
UPLOAD_CGI = "/cgi-bin/cstecgi.cgi"


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def build_analysis(root: Path = X5000R_ROOT):
    nested = build_nested_analysis(root)[-1]
    dispatch_path = nested.paths[0]
    content = (root / SERVER_PATH).read_bytes()
    source = _source(SERVER_PATH, content)
    protection = discover_mips_request_protection(
        source,
        content,
        (
            MipsRequestProtectionAnchor(
                "page:advance-config", PROTECTED_PAGE
            ),
            MipsRequestProtectionAnchor(dispatch_path.path_id, UPLOAD_CGI),
        ),
    )
    return source, nested, protection


def build_summary(root: Path = X5000R_ROOT) -> dict:
    source, nested, protection = build_analysis(root)
    assessments = {
        item.request_path: item for item in protection.assessments
    }
    page = assessments[PROTECTED_PAGE]
    upload = assessments[UPLOAD_CGI]
    dispatch = nested.paths[0]
    return {
        "schema_version": "firmatlas.mapping.x5000r-request-protection/v1alpha1",
        "source": {
            "path": source.canonical_path,
            "content_sha256": source.content_sha256,
            "size": source.size,
        },
        "protection_analysis": protection.to_dict(),
        "architecture_contrast": [
            {
                "request_path": page.request_path,
                "status": page.protection_status.value,
                "reason": (
                    "the .html suffix enters userloginAuth, then checkLoginUser "
                    "extracts SESSION_ID and resolves the session table"
                ),
            },
            {
                "request_path": upload.request_path,
                "status": upload.protection_status.value,
                "reason": (
                    "the CGI path matches none of the five suffix/path literals "
                    "that guard the userloginAuth call"
                ),
            },
        ],
        "cross_binary_path": [
            {
                "stage": "web_response_path_gate",
                "binary": source.canonical_path,
                "identity": upload.response_hook_identity,
                "guard_patterns": list(upload.guard_patterns),
            },
            {
                "stage": "session_authenticator_for_matching_pages",
                "binary": source.canonical_path,
                "identity": upload.authenticator_identity,
                "cookie": upload.cookie_name,
                "callsite": "0x{:08x}".format(upload.authenticator_callsite),
            },
            {
                "stage": "excluded_upload_cgi",
                "binary": source.canonical_path,
                "request_path": upload.request_path,
                "status": upload.protection_status.value,
            },
            {
                "stage": "nested_upload_dispatch",
                "binary": nested.source_path,
                "value": "{} -> {}".format(
                    dispatch.transport_selector, dispatch.nested_selector
                ),
                "identity": dispatch.dispatcher_identity,
            },
            {
                "stage": "upload_handler",
                "binary": nested.source_path,
                "identity": dispatch.handler_identity,
                "registration": "0x{:08x}".format(
                    dispatch.registration_address
                ),
            },
        ],
        "interpretation_boundary": {
            "supported": (
                "the shipped lighttpd path gate protects matching HTML/config "
                "responses with SESSION_ID validation but excludes the upload CGI "
                "path before cstecgi.cgi performs native dispatch"
            ),
            "not_claimed": (
                "live deployment reachability, external mediators, authorization "
                "policy, exploitability, or a vulnerability verdict"
            ),
        },
        "ghidra_trigger": {
            "triggered": False,
            "reason": (
                "the three protection functions are bounded exported symbols; "
                "their direct/GOT calls, branch targets, SESSION_ID constant, "
                "session lookup, and HTTP 302 enforcement replay deterministically"
            ),
            "future_trigger": (
                "use the isolated Ghidra Candidate Worker when stripped variants "
                "hide the auth hook, session flow, or branch corridor"
            ),
        },
        "obligation_transition": {
            "rejected": "obligation:x5000r-upload-auth-guard",
            "retained": "obligation:x5000r-upload-runtime-reachability",
            "reason": (
                "the expected pre-upload auth guard is absent from the proved "
                "static HTTP/CGI path; runtime reachability remains a separate claim"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(build_summary(args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
