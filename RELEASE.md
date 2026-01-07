# Release Guide for Instanton

This document provides step-by-step instructions for releasing Instanton to the public.

## Pre-Release Checklist

- [x] All tests passing (1009 tests)
- [x] Linting passes (ruff check src/)
- [x] LICENSE file exists
- [x] CONTRIBUTING.md exists
- [x] CHANGELOG.md is up to date
- [x] README.md is complete
- [x] .gitignore is configured
- [x] GitHub Actions CI workflow is set up
- [x] pyproject.toml has correct metadata

## Step 1: Create GitHub Repository

1. **Create a new repository** on GitHub:
   - Go to https://github.com/new
   - Organization: `DrRuin` (or your username)
   - Repository name: `instanton`
   - Description: "Tunnel through barriers, instantly - expose local services to the internet"
   - Public repository
   - Do NOT initialize with README (we have one)

2. **Initialize git and push**:
   ```bash
   cd "C:\Users\TITAN 18HX\Desktop\MCP\instanton"
   git init
   git add .
   git commit -m "Initial commit: Instanton v0.1.0"
   git branch -M main
   git remote add origin https://github.com/DrRuin/instanton.git
   git push -u origin main
   ```

## Step 2: Configure GitHub Repository

1. **Enable GitHub Actions**:
   - Go to Settings > Actions > General
   - Allow all actions and reusable workflows

2. **Set up branch protection** (optional but recommended):
   - Go to Settings > Branches > Add branch protection rule
   - Branch name pattern: `main`
   - Require status checks to pass before merging
   - Require pull request reviews

3. **Add repository topics**:
   - Go to repository main page
   - Click the gear icon next to "About"
   - Add topics: `tunnel`, `networking`, `python`, `proxy`, `https`, `localhost`, `ngrok-alternative`, `websocket`, `quic`

## Step 3: Set Up PyPI Publishing

### Option A: Trusted Publishing (Recommended)

1. **Create PyPI account** at https://pypi.org/account/register/

2. **Create the project on PyPI**:
   - Go to https://pypi.org/manage/projects/
   - Click "Add project" (or the project will be created on first publish)

3. **Configure trusted publishing**:
   - Go to https://pypi.org/manage/project/instanton/settings/publishing/
   - Add a new publisher:
     - Owner: `DrRuin`
     - Repository: `instanton`
     - Workflow name: `release.yml`
     - Environment name: `release`

4. **Create GitHub environment**:
   - Go to Settings > Environments > New environment
   - Name: `release`
   - Add protection rules if desired

### Option B: API Token

1. **Generate PyPI API token**:
   - Go to https://pypi.org/manage/account/token/
   - Create token with scope: Entire account (or project-specific after first upload)

2. **Add to GitHub secrets**:
   - Go to Settings > Secrets and variables > Actions
   - Add secret: `PYPI_API_TOKEN`

3. **Update release.yml** to use token instead of trusted publishing

## Step 4: Create First Release

1. **Verify version** in `pyproject.toml` and `src/instanton/__init__.py`:
   ```
   version = "0.1.0"
   __version__ = "0.1.0"
   ```

2. **Create a git tag**:
   ```bash
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```

3. **Create GitHub Release**:
   - Go to Releases > Create a new release
   - Choose tag: `v0.1.0`
   - Title: `Instanton v0.1.0`
   - Description: Copy from CHANGELOG.md
   - Click "Publish release"

4. **Verify PyPI publish**:
   - Check GitHub Actions for successful workflow
   - Verify at https://pypi.org/project/instanton/

## Step 5: Docker Hub Setup (Optional)

1. **Create Docker Hub account** at https://hub.docker.com/

2. **Create repositories**:
   - `instanton/instanton` (client)
   - `instanton/instanton-server` (server)

3. **Add GitHub secrets**:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Docker Hub access token

## Step 6: Post-Release

1. **Verify installation works**:
   ```bash
   pip install instanton
   instanton --help
   ```

2. **Announce the release**:
   - Twitter/X
   - Reddit (r/Python, r/selfhosted)
   - Hacker News
   - Dev.to
   - Python Discord servers

3. **Monitor issues**:
   - Watch for bug reports
   - Respond to questions

## Version Bumping for Future Releases

1. **Update version** in:
   - `pyproject.toml`: `version = "X.Y.Z"`
   - `src/instanton/__init__.py`: `__version__ = "X.Y.Z"`

2. **Update CHANGELOG.md** with new changes

3. **Create and push tag**:
   ```bash
   git add .
   git commit -m "Bump version to X.Y.Z"
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --tags
   ```

4. **Create GitHub Release** (triggers automatic PyPI publish)

## Useful Commands

```bash
# Build locally
pip install build
python -m build

# Test PyPI upload (test.pypi.org)
pip install twine
twine upload --repository testpypi dist/*

# Install from test PyPI
pip install --index-url https://test.pypi.org/simple/ instanton

# Check package metadata
pip install check-wheel-contents
check-wheel-contents dist/*.whl
```

## Troubleshooting

### PyPI Upload Fails
- Ensure version hasn't been used before
- Check API token permissions
- Verify trusted publishing configuration

### Tests Fail in CI
- Check Python version compatibility
- Ensure all dependencies are in pyproject.toml
- Review test output for specific failures

### Docker Build Fails
- Verify Dockerfile syntax
- Check base image availability
- Review build logs
