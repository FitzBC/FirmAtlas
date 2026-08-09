import hashlib
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    NativeRelationshipBindingStatus,
    NativeRelationshipKind,
    SourceArtifactEntry,
    discover_native_relationships,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path,
        path,
        "file",
        len(content),
        hashlib.sha256(content).hexdigest(),
    )


class NativeRelationshipProducerContractTests(unittest.TestCase):
    def test_elf_embedded_commands_publish_process_and_ipc_relationships(self):
        content = (
            b"\x7fELF\x01\x01" + b"\x00" * 58
            + b"killall -9 minidlna\x00"
            + b"cfm post netctrl 51?op=6,flag=1\x00"
        )

        result = discover_native_relationships(
            _source("bin/time_check", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(
            [NativeRelationshipKind.IPC_COMMAND, NativeRelationshipKind.PROCESS_CONTROL],
            [item.kind for item in result.relationships],
        )
        ipc, process = result.relationships
        self.assertEqual(("post", "netctrl", "51", "6"), (
            ipc.action, ipc.target, ipc.topic, ipc.operation,
        ))
        self.assertEqual(("flag=1",), ipc.arguments)
        self.assertEqual(("signal", "minidlna"), (process.action, process.target))
        self.assertEqual(
            NativeRelationshipBindingStatus.EMBEDDED_COMMAND,
            process.binding_status,
        )
        self.assertEqual(2, len(result.evidence_atoms))
        self.assertTrue(all(atom.confidence < 1.0 for atom in result.evidence_atoms))
        self.assertIn("callsite", result.open_obligation)

    def test_format_command_is_preserved_as_template_not_exact_operation(self):
        content = (
            b"\x7fELF\x01\x01" + b"\x00" * 58
            + b"cfm post time_check %d?op=%d,string_info=%s\x00"
        )

        result = discover_native_relationships(
            _source("bin/httpd", content), content
        )

        relationship = result.relationships[0]
        self.assertEqual("%d", relationship.topic)
        self.assertEqual("%d", relationship.operation)
        self.assertEqual(
            NativeRelationshipBindingStatus.EMBEDDED_COMMAND_TEMPLATE,
            relationship.binding_status,
        )

    def test_non_elf_content_is_unsupported(self):
        content = b"killall -9 minidlna\x00"

        result = discover_native_relationships(_source("etc/commands", content), content)

        self.assertEqual(CoverageStatus.UNSUPPORTED, result.coverage_status)
        self.assertEqual((), result.relationships)


if __name__ == "__main__":
    unittest.main()
