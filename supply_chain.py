"""Build and verify a reproducible archive with an SPDX 2.3 file inventory."""

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


PACKAGE = "greeter"
SOURCE_DIR = Path(__file__).resolve().parent / "src" / PACKAGE
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
DEFAULT_EPOCH = 315532800  # 1980-01-01, the earliest timestamp ZIP-based tools accept.
MAX_MEMBERS = 64
MAX_TOTAL_BYTES = 1024 * 1024
LICENSE = "MIT"
COPYRIGHT = "Copyright (c) 2026 Ibrahim Al-Shinnawi"
NAMESPACE_BASE = "https://github.com/1B05H1N/secure-supply-chain-demo/spdx"


class VerificationError(Exception):
    pass


@dataclass(frozen=True)
class BuildResult:
    archive: Path
    sbom: Path
    sha256: str


def check_version(version: str) -> str:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"Version must look like 1.2.3: {version!r}")
    return version


def source_files(source_dir: Path) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for path in sorted(source_dir.rglob("*")):
        relative = path.relative_to(source_dir).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise ValueError(f"Symbolic links are not packaged: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"Unsupported file type: {relative}")
        files.append((f"{PACKAGE}/{relative}", path.read_bytes()))
    if not files:
        raise ValueError("No source files found")
    return files


def archive_bytes(root: str, files: list[tuple[str, bytes]], epoch: int) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files:
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            info.mtime = epoch
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0, compresslevel=9) as stream:
        stream.write(tar_buffer.getvalue())
    return compressed.getvalue()


def verification_code(sha1_values: list[str]) -> str:
    return hashlib.sha1("".join(sorted(sha1_values)).encode("ascii")).hexdigest()


def spdx_document(
    version: str, archive_name: str, archive_sha256: str,
    members: list[tuple[str, bytes]], epoch: int,
) -> dict[str, object]:
    files = []
    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package",
    }]
    for index, (name, data) in enumerate(members, start=1):
        identifier = f"SPDXRef-File-{index}"
        files.append({
            "SPDXID": identifier,
            "fileName": f"./{name}",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": hashlib.sha1(data).hexdigest()},
                {"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()},
            ],
            "licenseConcluded": LICENSE,
            "copyrightText": COPYRIGHT,
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": identifier,
        })
    sha1_values = [file["checksums"][0]["checksumValue"] for file in files]
    created = datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PACKAGE}-{version}",
        "documentNamespace": f"{NAMESPACE_BASE}/{PACKAGE}-{version}-{archive_sha256}",
        "creationInfo": {"created": created, "creators": ["Tool: secure-supply-chain-demo"]},
        "packages": [{
            "SPDXID": "SPDXRef-Package",
            "name": PACKAGE,
            "versionInfo": version,
            "packageFileName": archive_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue": verification_code(sha1_values)},
            "checksums": [{"algorithm": "SHA256", "checksumValue": archive_sha256}],
            "licenseConcluded": LICENSE,
            "licenseDeclared": LICENSE,
            "copyrightText": COPYRIGHT,
        }],
        "files": files,
        "relationships": relationships,
    }


def build(version: str, output_dir: Path, epoch: int, source_dir: Path = SOURCE_DIR) -> BuildResult:
    check_version(version)
    if epoch < DEFAULT_EPOCH:
        raise ValueError("SOURCE_DATE_EPOCH must not be earlier than 1980-01-01")
    root = f"{PACKAGE}-{version}"
    files = source_files(source_dir)
    data = archive_bytes(root, files, epoch)
    digest = hashlib.sha256(data).hexdigest()
    members = [(f"{root}/{name}", content) for name, content in files]
    document = spdx_document(version, f"{root}.tar.gz", digest, members, epoch)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{root}.tar.gz"
    sbom = output_dir / f"{root}.spdx.json"
    archive.write_bytes(data)
    sbom.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return BuildResult(archive, sbom, digest)


def safe_member_name(name: str, root: str) -> str:
    path = PurePosixPath(name)
    if (
        "\\" in name or name.startswith("/") or not path.parts or path.parts[0] != root
        or any(part in {"", ".", ".."} for part in path.parts) or str(path) != name
        or len(path.parts) < 2
    ):
        raise VerificationError(f"Unsafe archive path: {name!r}")
    return name


def read_archive(data: bytes, root: str) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for count, member in enumerate(archive, start=1):
                if count > MAX_MEMBERS:
                    raise VerificationError("Archive has too many entries")
                name = safe_member_name(member.name, root)
                if not member.isreg():
                    raise VerificationError(f"Only regular files are allowed: {name}")
                if name in contents:
                    raise VerificationError(f"Duplicate archive entry: {name}")
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise VerificationError("Archive content exceeds the size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise VerificationError(f"Unreadable archive entry: {name}")
                contents[name] = stream.read()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise VerificationError(f"Invalid archive: {error}") from error
    return contents


def checksums(entry: dict[str, object]) -> dict[str, str]:
    values = entry.get("checksums")
    if not isinstance(values, list):
        raise VerificationError("SPDX entry has no checksums")
    result = {}
    for value in values:
        if not isinstance(value, dict):
            raise VerificationError("Invalid SPDX checksum")
        result[str(value.get("algorithm"))] = str(value.get("checksumValue"))
    return result


def verify(archive_path: Path, sbom_path: Path, expected_sha256: str | None = None) -> dict[str, object]:
    data = archive_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256.lower():
        raise VerificationError("Archive digest does not match the expected value")
    try:
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"Invalid SPDX JSON: {error}") from error
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise VerificationError("Expected an SPDX 2.3 JSON document")
    packages = document.get("packages")
    if not isinstance(packages, list) or len(packages) != 1 or not isinstance(packages[0], dict):
        raise VerificationError("Expected exactly one SPDX package")
    package = packages[0]
    try:
        version = check_version(str(package.get("versionInfo")))
    except ValueError as error:
        raise VerificationError(str(error)) from error
    root = f"{PACKAGE}-{version}"
    if package.get("name") != PACKAGE or package.get("packageFileName") != archive_path.name:
        raise VerificationError("SPDX package does not describe this archive")
    if checksums(package).get("SHA256") != digest:
        raise VerificationError("SPDX package checksum does not match the archive")

    files = document.get("files")
    if not isinstance(files, list):
        raise VerificationError("SPDX document has no file list")
    expected: dict[str, dict[str, str]] = {}
    for entry in files:
        if not isinstance(entry, dict) or not str(entry.get("fileName", "")).startswith("./"):
            raise VerificationError("Invalid SPDX file entry")
        name = str(entry["fileName"])[2:]
        if name in expected:
            raise VerificationError(f"Duplicate SPDX file entry: {name}")
        expected[name] = checksums(entry)

    contents = read_archive(data, root)
    if set(contents) != set(expected):
        missing = sorted(set(expected) - set(contents))
        unexpected = sorted(set(contents) - set(expected))
        raise VerificationError(f"Archive and inventory differ; missing={missing} unexpected={unexpected}")
    for name, content in contents.items():
        if (
            expected[name].get("SHA1") != hashlib.sha1(content).hexdigest()
            or expected[name].get("SHA256") != hashlib.sha256(content).hexdigest()
        ):
            raise VerificationError(f"Checksum mismatch: {name}")
    code = package.get("packageVerificationCode", {})
    if not isinstance(code, dict) or code.get("packageVerificationCodeValue") != verification_code(
        [values["SHA1"] for values in expected.values()]
    ):
        raise VerificationError("SPDX package verification code does not match")
    return {"archive": archive_path.name, "sha256": digest, "files": len(contents)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="Build the archive and SPDX inventory")
    build_parser.add_argument("--version", required=True)
    build_parser.add_argument("--output", type=Path, default=Path("dist"))
    verify_parser = commands.add_parser("verify", help="Verify an archive against its inventory")
    verify_parser.add_argument("archive", type=Path)
    verify_parser.add_argument("sbom", type=Path)
    verify_parser.add_argument("--expected-sha256", help="Digest obtained through a trusted channel")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "build":
            epoch = int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_EPOCH))
            result = build(arguments.version, arguments.output, epoch)
            print(json.dumps({"archive": str(result.archive), "sbom": str(result.sbom), "sha256": result.sha256}))
        else:
            print(json.dumps(verify(arguments.archive, arguments.sbom, arguments.expected_sha256)))
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
