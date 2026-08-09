import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    SourceArtifactEntry,
    WebConfigFindingKind,
    WebConfigPolicy,
    discover_web_configuration,
    replay_evidence,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


class WebConfigurationProducerContractTests(unittest.TestCase):
    def test_lighttpd_cgi_namespace_preserves_listener_root_and_execution_mode(self):
        content = b'''server.port = 80
server.document-root = "/www/"
$SERVER["socket"] == ":8080" { server.document-root = "/www/" }
$HTTP["url"] =~ "^(/~[^/]+)?/cgi-bin/" {
  cgi.assign = ( "" => "" )
}
'''

        result = discover_web_configuration(
            _source("lighttp/lighttpd.conf", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("lighttpd", result.detected_format)
        self.assertEqual(
            [
                (WebConfigFindingKind.LISTENER, None, "80", None),
                (WebConfigFindingKind.DOCUMENT_ROOT, "/", "/www/", None),
                (WebConfigFindingKind.LISTENER, None, "8080", None),
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/cgi-bin/",
                    "cgi",
                    "cgi_executor",
                ),
            ],
            [
                (item.kind, item.namespace, item.value, item.qualifier)
                for item in result.findings
            ],
        )
        self.assertEqual(
            {"listens_on", "maps_namespace", "binds_handler"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_proprietary_httpd_control_binds_alias_to_root_and_external_handler(self):
        content = b"""<? require('/etc/templates/troot.php'); ?>
Server {
  Virtual {
    Control {
      Alias /HNAP1
      Location /www/HNAP1
      External {
        /usr/sbin/hnap { hnap }
      }
      IndexNames { index.hnap }
    }
  }
}
"""

        result = discover_web_configuration(
            _source("etc/templates/httpd/httpd.php", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("proprietary_httpd", result.detected_format)
        self.assertEqual(
            [
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/HNAP1",
                    "/www/HNAP1",
                    "alias",
                    None,
                ),
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/HNAP1",
                    "/usr/sbin/hnap",
                    "external_handler",
                    "hnap",
                ),
            ],
            [
                (
                    item.kind,
                    item.namespace,
                    item.value,
                    item.qualifier,
                    item.related_value,
                )
                for item in result.findings
            ],
        )
        self.assertEqual(
            {"maps_namespace", "binds_handler"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_dynamic_php_text_does_not_masquerade_as_static_httpd_configuration(self):
        content = b'''<?
echo <<<CFG
Control {
 Alias /fake
 Location /www/fake
}
CFG;
?>'''

        result = discover_web_configuration(
            _source("etc/templates/httpd/generated.php", content), content
        )

        self.assertEqual(CoverageStatus.NOT_APPLICABLE, result.coverage_status)
        self.assertIsNone(result.detected_format)
        self.assertEqual((), result.findings)

    def test_nginx_server_and_location_blocks_preserve_scope(self):
        content = b"""http {
  server {
    listen 8180;
    location / { root /etc/nginx/conf; }
    location /cgi-bin/luci/ { fastcgi_pass 127.0.0.1:8188; }
    location ^~ /download/ { internal; alias /var/etc/upan/; }
  }
}
"""

        result = discover_web_configuration(
            _source("etc_ro/nginx/conf/nginx.conf", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("nginx", result.detected_format)
        self.assertEqual(
            {"lighttpd", "nginx", "posix_shell", "proprietary_httpd"},
            set(result.supported_formats),
        )
        self.assertEqual(
            [
                (WebConfigFindingKind.LISTENER, None, "8180", None),
                (WebConfigFindingKind.DOCUMENT_ROOT, "/", "/etc/nginx/conf", None),
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/cgi-bin/luci/",
                    "127.0.0.1:8188",
                    "fastcgi",
                ),
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/download/",
                    "/var/etc/upan/",
                    "internal_alias",
                ),
            ],
            [
                (item.kind, item.namespace, item.value, item.qualifier)
                for item in result.findings
            ],
        )
        self.assertEqual(
            {"listens_on", "maps_namespace"},
            {item.capability for item in result.evidence_atoms},
        )
        self.assertEqual(
            {item.evidence_id for item in result.evidence_atoms},
            {
                evidence_id
                for item in result.findings
                for evidence_id in item.evidence_ids
            },
        )
        self.assertIsInstance(json.dumps(result.to_dict()), str)
        self.assertEqual(
            "firmatlas.mapping.web-config-result/v1alpha1",
            result.to_dict()["schema_version"],
        )

    def test_nginx_auth_basic_records_protected_namespace(self):
        content = b"""server {
  location /admin/ {
    auth_basic "router";
    auth_basic_user_file /etc/nginx/passwd;
  }
  location /public/ { auth_basic off; }
}
"""

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content), content
        )

        protected = [
            item
            for item in result.findings
            if item.kind is WebConfigFindingKind.AUTH_REQUIREMENT
        ]
        self.assertEqual(
            [
                ("/admin/", "basic", "/etc/nginx/passwd"),
                ("/public/", "off", None),
            ],
            [(item.namespace, item.value, item.related_value) for item in protected],
        )
        self.assertEqual(
            {"requires_auth"},
            {
                item.capability
                for item in result.evidence_atoms
                if item.subject_ref in {finding.finding_id for finding in protected}
            },
        )

    def test_nginx_server_auth_and_internal_alias_are_order_independent(self):
        content = b"""server {
  auth_basic "router";
  location /private-download/ {
    alias /var/private/;
    internal;
  }
}
"""

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content), content
        )

        self.assertEqual(
            [
                (
                    WebConfigFindingKind.NAMESPACE_MAPPING,
                    "/private-download/",
                    "/var/private/",
                    "internal_alias",
                ),
                (WebConfigFindingKind.AUTH_REQUIREMENT, "/", "basic", None),
            ],
            [
                (item.kind, item.namespace, item.value, item.qualifier)
                for item in result.findings
            ],
        )
    def test_commented_nginx_examples_do_not_publish_findings(self):
        content = b"""# listen 9000;
# location /fake/ { proxy_pass http://127.0.0.1:99; }
server { # root /fake;
  listen 80;
}
"""

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content), content
        )

        self.assertEqual(1, len(result.findings))
        self.assertEqual("80", result.findings[0].value)

    def test_posix_startup_records_executed_service_and_listener(self):
        content = b"""#/bin/sh
mkdir /var/nginx
nginx -p /var/nginx
spawn-fcgi -a 127.0.0.1 -p 8188 /usr/bin/app_data_center
"""

        result = discover_web_configuration(
            _source("etc_ro/nginx/conf/nginx_init.sh", content), content
        )

        self.assertEqual("posix_shell", result.detected_format)
        self.assertEqual(
            [
                (WebConfigFindingKind.SERVICE_START, "nginx", "/var/nginx"),
                (
                    WebConfigFindingKind.SERVICE_START,
                    "/usr/bin/app_data_center",
                    "127.0.0.1:8188",
                ),
                (
                    WebConfigFindingKind.LISTENER,
                    "127.0.0.1:8188",
                    "/usr/bin/app_data_center",
                ),
            ],
            [
                (item.kind, item.value, item.related_value)
                for item in result.findings
            ],
        )
        self.assertEqual(
            {"starts", "listens_on"},
            {item.capability for item in result.evidence_atoms},
        )

    def test_shell_comments_and_non_execution_mentions_are_ignored(self):
        content = b"""#!/bin/sh
# nginx -p /fake
echo "spawn-fcgi -a 0.0.0.0 -p 9999 /fake"
enabled_nginx=true
"""

        result = discover_web_configuration(
            _source("etc/init.d/web.sh", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.findings)

    def test_unsupported_text_is_explicit_not_applicable(self):
        content = b"key=value\n"

        result = discover_web_configuration(
            _source("etc/application.conf", content), content
        )

        self.assertEqual(CoverageStatus.NOT_APPLICABLE, result.coverage_status)
        self.assertIsNone(result.detected_format)
        self.assertEqual((), result.findings)
        self.assertEqual("unsupported_format", result.diagnostics[0].code)

    def test_invalid_utf8_fails_instead_of_looking_empty(self):
        content = b"server { listen 80; }\xff"

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content), content
        )

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual(0, result.processed_bytes)
        self.assertEqual("invalid_utf8", result.diagnostics[0].code)

    def test_source_budget_is_a_policy_skip(self):
        content = b"server { listen 8180; }"

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content),
            content,
            WebConfigPolicy(max_source_bytes=8),
        )

        self.assertEqual(CoverageStatus.SKIPPED_BY_POLICY, result.coverage_status)
        self.assertEqual(0, result.processed_bytes)
        self.assertEqual("source_budget_exceeded", result.diagnostics[0].code)

    def test_finding_budget_returns_an_exact_partial_prefix(self):
        content = b"""server {
  listen 80;
  listen 8080;
  listen 8180;
}
"""

        result = discover_web_configuration(
            _source("etc/nginx/nginx.conf", content),
            content,
            WebConfigPolicy(max_findings=2),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(["80", "8080"], [item.value for item in result.findings])
        self.assertEqual(2, len(result.evidence_atoms))
        self.assertEqual("finding_budget_exceeded", result.diagnostics[0].code)

    def test_actual_ac9_configuration_replays_expected_architecture(self):
        repository = Path(__file__).resolve().parents[1]
        root = (
            repository.parent
            / "iot_seedintelligentanalysis"
            / "_tenda_ac9.zip.extracted"
            / "squashfs-root"
        )
        config_path = root / "etc_ro/nginx/conf/nginx.conf"
        startup_path = root / "etc_ro/nginx/conf/nginx_init.sh"
        if not config_path.exists() or not startup_path.exists():
            self.skipTest("local AC9 representative sample is unavailable")

        config = config_path.read_bytes()
        startup = startup_path.read_bytes()
        config_source = _source("etc_ro/nginx/conf/nginx.conf", config)
        startup_source = _source("etc_ro/nginx/conf/nginx_init.sh", startup)
        config_result = discover_web_configuration(config_source, config)
        startup_result = discover_web_configuration(startup_source, startup)

        self.assertLessEqual(
            {"8180", "127.0.0.1:8188", "/etc/nginx/conf", "/var/etc/upan/"},
            {item.value for item in config_result.findings},
        )
        self.assertEqual(
            {"nginx", "/usr/bin/app_data_center", "127.0.0.1:8188"},
            {item.value for item in startup_result.findings},
        )
        self.assertTrue(
            all(
                atom.source_span.excerpt_sha256
                for result in (config_result, startup_result)
                for atom in result.evidence_atoms
            )
        )
        for result, source, content in (
            (config_result, config_source, config),
            (startup_result, startup_source, startup),
        ):
            for atom in result.evidence_atoms:
                self.assertTrue(replay_evidence(atom, source, content))

    def test_actual_dap3520_httpd_template_replays_hnap_binding(self):
        base = Path(
            "../iot_seedintelligentanalysis/binwalk_result/类型6/BM-2024-00027"
        )
        roots = list(base.glob(
            "*.ZIP.extracted/_*.bin.extracted/squashfs-root"
        ))
        if not roots:
            self.skipTest("local DAP-3520 representative sample is unavailable")
        path = roots[0] / "etc/templates/httpd/httpd.php"
        content = path.read_bytes()
        self.assertEqual(
            "2ffdadc17fbbe376e91c6657b1b99a54342f93a53c464df0a2089c14751069f9",
            hashlib.sha256(content).hexdigest(),
        )
        source = _source("etc/templates/httpd/httpd.php", content)

        result = discover_web_configuration(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(5, len(result.findings))
        hnap = [item for item in result.findings if item.namespace == "/HNAP1"]
        self.assertEqual(
            [
                ("/www/HNAP1", "alias", None),
                ("/usr/sbin/hnap", "external_handler", "hnap"),
            ],
            [(item.value, item.qualifier, item.related_value) for item in hnap],
        )
        self.assertEqual(12, len(result.evidence_atoms))
        self.assertTrue(
            all(replay_evidence(atom, source, content) for atom in result.evidence_atoms)
        )


if __name__ == "__main__":
    unittest.main()
