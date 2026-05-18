# Contributing to AI Guardian

Thank you for your interest in contributing! AI Guardian uses a standard fork-based workflow.

## Quick Start

```bash
gh repo fork itdove/ai-guardian --clone
cd ai-guardian
git checkout -b feature/your-change
# make changes, commit, push
gh pr create --web
```

## Branch Naming

- `feature/description` -- New features
- `fix/description` -- Bug fixes
- `docs/description` -- Documentation
- `refactor/description` -- Refactoring
- `test/description` -- Tests

## Commit Messages

```
<type>: <subject>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Pull Request Checklist

- [ ] Tests pass: `pytest`
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] One feature/fix per PR
- [ ] No unrelated changes

## Developer Guide

For detailed setup, testing, architecture, and development workflows, see **[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)**.

## Release Process

Contributors cannot create releases. Submit PRs with features/fixes; maintainers handle releases. See [RELEASING.md](RELEASING.md).

## Code of Conduct

Be respectful, accept constructive criticism, and focus on what's best for the project.

## Security Issues

Report security vulnerabilities privately to the maintainers -- do not open a public issue.
