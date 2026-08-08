import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    AnalyzerIdentity,
    EvidenceClaim,
    EvidenceAtom,
    ObservationKind,
    SourceArtifactEntry,
    SpanKind,
    SpanSelection,
    capture_evidence,
    replay_evidence,
)


class EvidenceCaptureContractTests(unittest.TestCase):
    def test_text_selection_becomes_replayable_evidence_atom(self):
        content = b'const url = "/goform/SetStaticRouteCfg";\n'
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/static_route.js",
            original_path="webroot_ro/js/static_route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        evidence = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(
                kind=SpanKind.TEXT_UTF8,
                start_byte=13,
                end_byte=38,
            ),
            claim=EvidenceClaim(
                subject_ref="interface:goform-set-static-route",
                predicate="constructs_request",
                object_value="/goform/SetStaticRouteCfg",
                observation_kind=ObservationKind.DIRECT_STATIC,
                capability="constructs_request",
                confidence=1.0,
            ),
            producer=AnalyzerIdentity(name="frontend-javascript", version="0.1.0"),
        )

        self.assertEqual("webroot_ro/js/static_route.js", evidence.source_span.artifact_path)
        self.assertEqual(SpanKind.TEXT_UTF8, evidence.source_span.span_kind)
        self.assertEqual(13, evidence.source_span.start_byte)
        self.assertEqual(38, evidence.source_span.end_byte)
        self.assertEqual(1, evidence.source_span.start_line)
        self.assertEqual(14, evidence.source_span.start_column)
        self.assertEqual(1, evidence.source_span.end_line)
        self.assertEqual(39, evidence.source_span.end_column)
        self.assertEqual(
            "17591bf7217baf2f2c4fc3b0eb7ace86055925fba126f741b016dade963a27c0",
            evidence.source_span.excerpt_sha256,
        )
        self.assertEqual(
            "text_utf8:bytes=13-38;lines=1:14-1:39",
            evidence.source_span.locator,
        )
        self.assertEqual(
            "evidence:132a033d5e7335344900861cdf918c569125be98d3a9991386a428c20fcfe947",
            evidence.evidence_id,
        )
        self.assertEqual(
            "firmatlas.mapping.evidence/v1alpha1",
            evidence.to_dict()["schema_version"],
        )
        self.assertEqual(evidence, type(evidence).from_dict(evidence.to_dict()))

        payload = evidence.to_dict()
        payload["schema_version"] = "firmatlas.mapping.evidence/v999"
        with self.assertRaisesRegex(ValueError, "evidence schema_version"):
            type(evidence).from_dict(payload)

    def test_non_content_inventory_entry_cannot_publish_evidence(self):
        content = b"/goform/SetStaticRouteCfg"
        source = SourceArtifactEntry(
            canonical_path="webroot_ro/js/route-link",
            original_path="webroot_ro/js/route-link",
            kind="symlink",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
            link_target="../../outside",
        )

        with self.assertRaisesRegex(ValueError, "source kind symlink"):
            capture_evidence(
                source=source,
                content=content,
                selection=SpanSelection(
                    kind=SpanKind.TEXT_UTF8,
                    start_byte=0,
                    end_byte=len(content),
                ),
                claim=EvidenceClaim(
                    subject_ref="interface:route",
                    predicate="mentions_endpoint",
                    object_value="/goform/SetStaticRouteCfg",
                    observation_kind=ObservationKind.DIRECT_STATIC,
                    capability="mentions_endpoint",
                    confidence=1.0,
                ),
                producer=AnalyzerIdentity(name="text-index", version="0.1.0"),
            )

    def test_direct_static_value_must_be_present_in_the_selected_span(self):
        content = b'route = "/goform/Actual";'
        source = SourceArtifactEntry(
            canonical_path="www/route.js",
            original_path="www/route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        with self.assertRaisesRegex(ValueError, "direct_static object_value"):
            capture_evidence(
                source=source,
                content=content,
                selection=SpanSelection(
                    kind=SpanKind.TEXT_UTF8,
                    start_byte=9,
                    end_byte=23,
                ),
                claim=EvidenceClaim(
                    subject_ref="interface:invented",
                    predicate="mentions_endpoint",
                    object_value="/goform/Invented",
                    observation_kind=ObservationKind.DIRECT_STATIC,
                    capability="mentions_endpoint",
                    confidence=1.0,
                ),
                producer=AnalyzerIdentity(name="text-index", version="0.1.0"),
            )

    def test_binary_selection_has_exact_bytes_without_text_coordinates(self):
        content = b"\x00\xff/HNAP1\x00"
        source = SourceArtifactEntry(
            canonical_path="bin/httpd",
            original_path="bin/httpd",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        evidence = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(kind=SpanKind.BINARY, start_byte=2, end_byte=8),
            claim=EvidenceClaim(
                subject_ref="interface:hnap1",
                predicate="mentions_endpoint",
                object_value="/HNAP1",
                observation_kind=ObservationKind.DIRECT_STATIC,
                capability="mentions_endpoint",
                confidence=1.0,
            ),
            producer=AnalyzerIdentity(name="binary-string-index", version="0.1.0"),
        )

        self.assertEqual("binary:bytes=2-8", evidence.source_span.locator)
        self.assertIsNone(evidence.source_span.start_line)
        self.assertIsNone(evidence.source_span.start_column)
        self.assertEqual(
            hashlib.sha256(b"/HNAP1").hexdigest(),
            evidence.source_span.excerpt_sha256,
        )

    def test_content_must_still_match_the_inventory_entry(self):
        content = b"/goform/Expected"
        source = SourceArtifactEntry(
            canonical_path="www/route.js",
            original_path="www/route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(b"same-sized-change").hexdigest(),
        )

        with self.assertRaisesRegex(ValueError, "digest does not match"):
            capture_evidence(
                source=source,
                content=content,
                selection=SpanSelection(
                    kind=SpanKind.TEXT_UTF8,
                    start_byte=0,
                    end_byte=len(content),
                ),
                claim=EvidenceClaim(
                    subject_ref="interface:expected",
                    predicate="mentions_endpoint",
                    object_value="/goform/Expected",
                    observation_kind=ObservationKind.DIRECT_STATIC,
                    capability="mentions_endpoint",
                    confidence=1.0,
                ),
                producer=AnalyzerIdentity(name="text-index", version="0.1.0"),
            )

    def test_text_offsets_cannot_split_a_utf8_codepoint(self):
        content = "路/goform/X".encode("utf-8")
        source = SourceArtifactEntry(
            canonical_path="www/route.js",
            original_path="www/route.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

        with self.assertRaisesRegex(ValueError, "codepoint-aligned"):
            capture_evidence(
                source=source,
                content=content,
                selection=SpanSelection(
                    kind=SpanKind.TEXT_UTF8,
                    start_byte=1,
                    end_byte=len(content),
                ),
                claim=EvidenceClaim(
                    subject_ref="interface:x",
                    predicate="mentions_endpoint",
                    object_value="/goform/X",
                    observation_kind=ObservationKind.DIRECT_STATIC,
                    capability="mentions_endpoint",
                    confidence=1.0,
                ),
                producer=AnalyzerIdentity(name="text-index", version="0.1.0"),
            )

    def test_replay_returns_only_the_verified_source_excerpt(self):
        content = b'const route = "/goform/SetName";\n'
        source = SourceArtifactEntry(
            canonical_path="www/name.js",
            original_path="www/name.js",
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
        evidence = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(
                kind=SpanKind.TEXT_UTF8,
                start_byte=15,
                end_byte=30,
            ),
            claim=EvidenceClaim(
                subject_ref="interface:set-name",
                predicate="constructs_request",
                object_value="/goform/SetName",
                observation_kind=ObservationKind.DIRECT_STATIC,
                capability="constructs_request",
                confidence=1.0,
            ),
            producer=AnalyzerIdentity(name="frontend-javascript", version="0.1.0"),
        )

        self.assertEqual(
            b"/goform/SetName",
            replay_evidence(evidence=evidence, source=source, content=content),
        )

        changed = content.replace(b"SetName", b"GetName")
        with self.assertRaisesRegex(ValueError, "content digest"):
            replay_evidence(evidence=evidence, source=source, content=changed)

    def test_documented_tenda_atoms_remain_compatible_with_the_contract(self):
        fixture = (
            Path(__file__).parents[1]
            / "docs"
            / "firmware-mapping"
            / "samples"
            / "tenda-ac9-m1-evidence-atoms.json"
        )
        payload = json.loads(fixture.read_text(encoding="utf-8"))

        atoms = tuple(
            EvidenceAtom.from_dict(item) for item in payload["evidence_atoms"]
        )

        self.assertEqual(2, len(atoms))
        self.assertEqual(
            {"goform/GetStaticRouteCfg", "goform/SetStaticRouteCfg"},
            {atom.object_value for atom in atoms},
        )
        self.assertEqual(
            {
                "text_utf8:bytes=431-455;lines=18:14-18:38",
                "text_utf8:bytes=472-496;lines=19:14-19:38",
            },
            {atom.source_span.locator for atom in atoms},
        )
        self.assertEqual(2, payload["replay"]["verified_count"])


if __name__ == "__main__":
    unittest.main()
