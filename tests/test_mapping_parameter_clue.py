import hashlib
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    FrontendAssetInput,
    ParameterClueArtifact,
    ParameterClueArtifactRole,
    SourceArtifactEntry,
    discover_frontend_asset_graph,
    trace_frontend_parameter_clues,
)


def artifact(path: str, content: bytes) -> tuple[SourceArtifactEntry, bytes]:
    return (
        SourceArtifactEntry(
            path, path, "file", len(content), hashlib.sha256(content).hexdigest()
        ),
        content,
    )


class FrontendParameterClueContractTests(unittest.TestCase):
    def test_indexes_exact_cross_artifact_tokens_and_preserves_negative_result(self):
        source, content = artifact(
            "webroot_ro/js/dlna.js",
            b'''var pageModel=R.pageModel({setUrl:"/goform/SetDlnaCfg"});
var moduleModel=R.moduleModel({getSubmitData:function(){
return "dlnaEn="+enabled+"&deviceName="+name+"&scanList="+list;}});''',
        )
        graph = discover_frontend_asset_graph((FrontendAssetInput(source, content),))
        config_source, config = artifact(
            "etc/minidlna.conf", b"enabled=dlnaEn\nfriendly=deviceName\n"
        )
        native_source, native = artifact(
            "bin/httpd", b"prefixdeviceNameSuffix\x00deviceName\x00"
        )

        result = trace_frontend_parameter_clues(
            graph,
            (
                ParameterClueArtifact(
                    config_source, config, ParameterClueArtifactRole.CONFIGURATION
                ),
                ParameterClueArtifact(
                    native_source, native, ParameterClueArtifactRole.NATIVE
                ),
            ),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        assessments = {item.parameter_name: item for item in result.assessments}
        self.assertEqual(1, len(assessments["dlnaEn"].occurrences))
        self.assertEqual(2, len(assessments["deviceName"].occurrences))
        self.assertEqual(0, len(assessments["scanList"].occurrences))
        self.assertEqual(
            "no_external_clue", assessments["scanList"].assessment_status
        )
        native_occurrence = next(
            item
            for item in assessments["deviceName"].occurrences
            if item.artifact_role is ParameterClueArtifactRole.NATIVE
        )
        self.assertEqual(native.rindex(b"deviceName"), native_occurrence.start_byte)
        self.assertIn(
            "external_parameter_token",
            {item.capability for item in result.evidence_atoms},
        )

    def test_budget_exhaustion_is_explicit_partial_coverage(self):
        source, content = artifact(
            "www/a.js", b'''var pageModel=R.pageModel({setUrl:"/save"});
var moduleModel=R.moduleModel({getSubmitData:function(){return "name="+value;}});'''
        )
        graph = discover_frontend_asset_graph((FrontendAssetInput(source, content),))
        other_source, other = artifact("etc/config", b"name=name")

        from firmatlas.mapping import ParameterCluePolicy

        result = trace_frontend_parameter_clues(
            graph,
            (ParameterClueArtifact(other_source, other, ParameterClueArtifactRole.CONFIGURATION),),
            ParameterCluePolicy(max_total_bytes=4),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("coverage_limited", result.assessments[0].assessment_status)
        self.assertIn("parameter_clue.byte_budget_exhausted", result.diagnostics)


if __name__ == "__main__":
    unittest.main()
