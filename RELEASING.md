# Releasing

ghostprobe publishes to PyPI through GitHub Actions Trusted Publishing (OIDC).
No API token is stored anywhere: PyPI verifies each upload came from this repo's
`publish.yml` workflow.

## One-time setup (on PyPI)

On pypi.org, open the ghostprobe project, go to **Manage → Publishing**, and add
a GitHub Actions trusted publisher with these exact values:

- Owner: `joemunene-by`
- Repository: `ghostprobe`
- Workflow name: `publish.yml`
- Environment name: `pypi`

## Cutting a release

1. Bump the version in **both** `pyproject.toml` and `ghostprobe/__init__.py`.
2. Add a `CHANGELOG.md` entry.
3. Commit and push to `main`; let CI pass.
4. Create the release on a matching tag:

   ```
   gh release create v0.3.1 --title v0.3.1 --generate-notes
   ```

The `Publish to PyPI` workflow then builds and uploads automatically. The build
uses the version in `pyproject.toml`, so make sure step 1 is done before the
release, or the upload will fail (PyPI versions are immutable and cannot be
re-uploaded).
