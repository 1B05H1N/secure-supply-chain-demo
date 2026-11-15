import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import supply_chain
from supply_chain import VerificationError, build, verify


EPOCH = 1767225600


def tar_gz(entries: list[tarfile.TarInfo | tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                archive.addfile(entry)
            else:
                name, data = entry
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


class SupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.result = build("1.0.0", self.root / "dist", EPOCH)

    def members(self) -> list[tuple[str, bytes]]:
        with tarfile.open(self.result.archive, "r:gz") as archive:
            return [
                (member.name, archive.extractfile(member).read())  # type: ignore[union-attr]
                for member in archive.getmembers()
            ]

    def replace_archive(self, data: bytes) -> None:
        self.result.archive.write_bytes(data)
        document = json.loads(self.result.sbom.read_text())
        document["packages"][0]["checksums"][0]["checksumValue"] = hashlib.sha256(data).hexdigest()
        self.result.sbom.write_text(json.dumps(document))

    def assert_rejected(self, message: str) -> None:
        with self.assertRaisesRegex(VerificationError, message):
            verify(self.result.archive, self.result.sbom)

    def test_builds_are_byte_for_byte_reproducible(self) -> None:
        second = build("1.0.0", self.root / "second", EPOCH)
        self.assertEqual(self.result.archive.read_bytes(), second.archive.read_bytes())
        self.assertEqual(self.result.sbom.read_bytes(), second.sbom.read_bytes())

    def test_clean_build_verifies_and_inventory_matches_archive(self) -> None:
        summary = verify(self.result.archive, self.result.sbom, self.result.sha256)
        self.assertEqual(summary["files"], len(self.members()))
        names = {entry["fileName"] for entry in json.loads(self.result.sbom.read_text())["files"]}
        self.assertEqual(names, {f"./{name}" for name, _ in self.members()})

    def test_expected_digest_from_trusted_channel_must_match(self) -> None:
        with self.assertRaisesRegex(VerificationError, "expected value"):
            verify(self.result.archive, self.result.sbom, "0" * 64)

    def test_replaced_archive_fails_even_with_updated_package_checksum(self) -> None:
        members = self.members()
        members[0] = (members[0][0], members[0][1] + b"\nprint('changed')\n")
        self.replace_archive(tar_gz(members))
        self.assert_rejected("Checksum mismatch")

    def test_replaced_archive_fails_package_checksum(self) -> None:
        self.result.archive.write_bytes(tar_gz(self.members()))
        self.assert_rejected("package checksum")

    def test_unsafe_or_unexpected_entries_are_rejected(self) -> None:
        link = tarfile.TarInfo("greeter-1.0.0/greeter/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        directory = tarfile.TarInfo("greeter-1.0.0/greeter/extra")
        directory.type = tarfile.DIRTYPE
        cases = {
            "traversal": ("greeter-1.0.0/../evil.py", b"x"),
            "absolute": ("/tmp/evil.py", b"x"),
            "outside root": ("other-1.0.0/evil.py", b"x"),
            "backslash": ("greeter-1.0.0\\evil.py", b"x"),
            "extra file": ("greeter-1.0.0/greeter/evil.py", b"x"),
            "symbolic link": link,
            "directory": directory,
        }
        original = self.members()
        for label, entry in cases.items():
            with self.subTest(label):
                self.replace_archive(tar_gz([*original, entry]))
                with self.assertRaises(VerificationError):
                    verify(self.result.archive, self.result.sbom)

    def test_duplicate_entries_are_rejected(self) -> None:
        members = self.members()
        self.replace_archive(tar_gz([*members, members[0]]))
        self.assert_rejected("Duplicate archive entry")

    def test_missing_file_is_rejected(self) -> None:
        self.replace_archive(tar_gz(self.members()[1:]))
        self.assert_rejected("missing=")

    def test_tampered_inventory_is_rejected(self) -> None:
        document = json.loads(self.result.sbom.read_text())
        document["files"][0]["checksums"][1]["checksumValue"] = "0" * 64
        self.result.sbom.write_text(json.dumps(document))
        self.assert_rejected("Checksum mismatch")

    def test_inventory_for_another_archive_is_rejected(self) -> None:
        other = build("1.0.1", self.root / "other", EPOCH)
        with self.assertRaisesRegex(VerificationError, "does not describe"):
            verify(self.result.archive, other.sbom)

    def test_archive_size_limits(self) -> None:
        with mock.patch.object(supply_chain, "MAX_TOTAL_BYTES", 10):
            self.assert_rejected("size limit")
        with mock.patch.object(supply_chain, "MAX_MEMBERS", 1):
            self.assert_rejected("too many entries")

    def test_build_rejects_symlinks_and_invalid_versions(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "app.py").write_text("print('x')\n")
        (source / "link.py").symlink_to(source / "app.py")
        with self.assertRaisesRegex(ValueError, "Symbolic links"):
            build("1.0.0", self.root / "bad", EPOCH, source)
        for version in ("1.0", "v1.0.0", "1.0.0/../x"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                build(version, self.root / "bad", EPOCH)

    def test_cli_exit_codes(self) -> None:
        with mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(supply_chain.main(["verify", str(self.result.archive), str(self.result.sbom)]), 0)
        self.result.archive.write_bytes(b"not an archive")
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(supply_chain.main(["verify", str(self.result.archive), str(self.result.sbom)]), 1)
            self.assertEqual(supply_chain.main(["build", "--version", "bad"]), 2)


if __name__ == "__main__":
    unittest.main()
