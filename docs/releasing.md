# Releasing

1. Update `CHANGELOG.md`.
2. Set the same `X.Y.Z` version in the root and optional CAN `pyproject.toml` files.
3. Run the complete CI suite and local Debian build.
4. Create an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "PerfektBlue vX.Y.Z"
   git push origin vX.Y.Z
   ```

The release workflow verifies version alignment, runs tests, builds the wheel and `.deb`,
validates clean installation, generates SHA-256 checksums and an SPDX SBOM, creates provenance,
and publishes all artifacts to a GitHub Release.

