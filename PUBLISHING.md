# Publishing DataCloak to PyPI

A complete step-by-step guide to build, test, and publish DataCloak.

---

## Prerequisites

- Python 3.11+
- A [PyPI account](https://pypi.org/account/register/) (and optionally [TestPyPI](https://test.pypi.org/account/register/))
- `build` and `twine` installed

```bash
pip install build twine hatchling
```

---

## Step 1 — Clone and set up the project

```bash
git clone https://github.com/your-org/datacloak.git
cd datacloak

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

---

## Step 2 — Run tests and verify coverage

```bash
pytest --cov=datacloak --cov-report=term-missing

# Expect: TOTAL coverage ≥ 90%
```

---

## Step 3 — Bump the version (Semantic Versioning)

Edit the version in **one place**:

```toml
# pyproject.toml
[project]
version = "0.2.0"   # ← update here
```

Also update `datacloak/__init__.py`:

```python
__version__ = "0.2.0"
```

Commit:
```bash
git add pyproject.toml datacloak/__init__.py
git commit -m "chore: bump version to 0.2.0"
git tag v0.2.0
```

---

## Step 4 — Build the distribution packages

```bash
# Remove any old builds
rm -rf dist/ build/ *.egg-info

# Build both wheel and source distribution
python -m build
```

You should now have:
```
dist/
  datacloak-0.2.0-py3-none-any.whl
  datacloak-0.2.0.tar.gz
```

---

## Step 5 — Validate the built packages

```bash
twine check dist/*
```

Expected output:
```
Checking dist/datacloak-0.2.0-py3-none-any.whl: PASSED
Checking dist/datacloak-0.2.0.tar.gz: PASSED
```

---

## Step 6 — Test upload to TestPyPI (recommended)

```bash
twine upload --repository testpypi dist/*
```

You'll be prompted for your TestPyPI username and password (or use an API token).

Verify the install from TestPyPI:
```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ datacloak
```

Test it:
```python
from datacloak import mask
print(mask("Phone: 9876543210"))
# Phone: ******3210
```

---

## Step 7 — Publish to production PyPI

Once you're satisfied with the TestPyPI result:

```bash
twine upload dist/*
```

You'll be prompted for your PyPI credentials. **Use an API token** (safer than password):

1. Go to https://pypi.org/manage/account/token/
2. Create a token scoped to `datacloak`
3. Set username `__token__` and the token as password

Or configure `~/.pypirc`:

```ini
[pypi]
  username = __token__
  password = pypi-AgEIcHlwaS5vcmcA...your-token-here
```

---

## Step 8 — Verify the production install

```bash
pip install datacloak
datacloak --version
# datacloak, version 0.2.0
```

---

## Step 9 — Create a GitHub Release

```bash
git push origin main --tags
```

Then on GitHub:
- Go to **Releases** → **Draft a new release**
- Select tag `v0.2.0`
- Paste the relevant section from `CHANGELOG.md`
- Attach `dist/*.whl` and `dist/*.tar.gz`
- Publish

---

## Automated Publishing with GitHub Actions (recommended)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write  # OIDC trusted publishing — no API token needed!

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Build
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

With this workflow, simply creating a GitHub Release triggers an automatic PyPI publish — no secrets required (uses [OIDC Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

---

## Versioning Strategy

DataCloak follows [Semantic Versioning](https://semver.org/):

| Change type | Version bump | Example |
|---|---|---|
| Bug fixes, documentation | Patch | `0.1.0` → `0.1.1` |
| New features, new detectors | Minor | `0.1.1` → `0.2.0` |
| Breaking API changes | Major | `0.2.0` → `1.0.0` |

---

## Checklist before each release

- [ ] All tests pass: `pytest`
- [ ] Coverage ≥ 90%: `pytest --cov=datacloak`
- [ ] No lint errors: `ruff check datacloak`
- [ ] No type errors: `mypy datacloak`
- [ ] `CHANGELOG.md` updated
- [ ] Version bumped in `pyproject.toml` and `datacloak/__init__.py`
- [ ] `twine check dist/*` passes
- [ ] TestPyPI upload and smoke test done
