# Secure supply-chain demo

A small Python package built into a byte-for-byte reproducible archive with an
SPDX 2.3 file inventory. The release workflow signs build provenance and the
SBOM with GitHub artifact attestations, then verifies both against the expected
repository, workflow, tag, and commit before publishing anything.

This is the implementation for the
[software release case study](https://github.com/1B05H1N/security-architecture-case-studies/blob/main/cases/software-release.md).
It uses only Python's standard library. Use Python 3.11 or newer.

## Run locally

```sh
python3 -m unittest -v
SOURCE_DATE_EPOCH=1767225600 python3 supply_chain.py build --version 1.0.0
python3 supply_chain.py verify dist/greeter-1.0.0.tar.gz dist/greeter-1.0.0.spdx.json
```

Building twice with the same source, version, `SOURCE_DATE_EPOCH`, and Python
version produces identical archive and SBOM bytes. CI checks this on every push.

## What the verifier rejects

The verifier reads the archive in memory and never writes its entries to disk.
It fails on:

- path traversal, absolute paths, backslashes, and entries outside the
  versioned root directory
- symbolic links, hard links, directories, and other non-regular entries
- duplicate entries, too many entries, or too much content
- any file missing from, added to, or changed relative to the SPDX inventory
- an SPDX package checksum or verification code that does not match
- an archive digest that differs from `--expected-sha256`, when supplied

Matching the SBOM proves only that the archive and inventory agree. Anyone who
can replace the archive can also replace an unsigned SBOM, so a local check is
not evidence of who built the release.

## Release flow

Pushing a tag such as `v1.0.0` runs [release.yml](.github/workflows/release.yml):

1. **Build** (read-only contents): run tests, build with the commit time as
   `SOURCE_DATE_EPOCH`, verify locally, then attest build provenance and the SBOM.
2. **Publish** (separate job): download the artifacts and run
   `gh attestation verify` for both attestations, requiring this repository, the
   release workflow, the exact tag and commit, and a GitHub-hosted runner. The
   GitHub release is created only if both checks pass.

Every action is pinned to a full commit SHA. Pull-request CI has read-only
permissions and cannot sign or publish.

## Verify a release as a consumer

```sh
gh release download v1.0.0 --repo 1B05H1N/secure-supply-chain-demo
gh attestation verify greeter-1.0.0.tar.gz \
  --repo 1B05H1N/secure-supply-chain-demo \
  --signer-workflow github.com/1B05H1N/secure-supply-chain-demo/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.0 \
  --deny-self-hosted-runners
gh attestation verify greeter-1.0.0.tar.gz \
  --repo 1B05H1N/secure-supply-chain-demo \
  --predicate-type https://spdx.dev/Document/v2.3
python3 supply_chain.py verify greeter-1.0.0.tar.gz greeter-1.0.0.spdx.json
```

Use a tag and commit you expect from a trusted source, such as a reviewed
release announcement, rather than values copied from the downloaded files.

## Limits

- The SBOM inventories the files in the archive. It does not cover the Python
  interpreter, operating system, or transitive dependencies; a real project
  needs a dependency-aware generator.
- Reproducibility shows the same inputs produce the same output. It does not
  prove the inputs were safe.
- A valid attestation shows which workflow built the artifact. It does not show
  that the workflow, runner, or maintainer account was uncompromised, or that
  the software is free of vulnerabilities.
- Archive bytes depend on the `zlib` build. Compare builds made with the same
  Python version and platform.

## License

[MIT](LICENSE)
