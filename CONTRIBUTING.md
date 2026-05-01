# Contributing

Thanks for improving sambatui. This document is for contributors and maintainers.
User installation, configuration, and operation live in [README.md](README.md).
Security reporting lives in [SECURITY.md](SECURITY.md).

## Setup

This project uses `mise` for tools/tasks and `uv` for Python dependencies.

1. Install and enable `mise`.
2. Clone the repository.
3. Trust the project configuration:

   ```sh
   mise trust
   ```

4. Install dependencies:

   ```sh
   mise run install
   ```

5. Run the full quality gate:

   ```sh
   mise run check
   ```

## Project layout

| Path | Purpose |
| --- | --- |
| `src/sambatui/` | Application source code. |
| `tests/` | Unit and behavior tests. |
| `README.md` | User-facing install, configuration, usage, and operational notes. |
| `CONTRIBUTING.md` | Developer setup, workflow, quality gates, and release process. |
| `SECURITY.md` | Vulnerability reporting process. |
| `AGENTS.md` | Instructions for AI coding agents working in this repository. |
| `AUDIT.md` | Security audit notes and follow-up context. |
| `CHANGELOG.md` | Release history generated/maintained during releases. |

## Development workflow

Use `mise` tasks rather than invoking repository tools directly:

| Task | Purpose |
| --- | --- |
| `mise run sambatui` | Run the app from checkout. |
| `mise run install` | Install locked project and development dependencies. |
| `mise run fix` | Run hk-managed formatters and fixers. |
| `mise run lint` | Run hk-managed checks. |
| `mise run test` | Run pytest in parallel with coverage reporting. |
| `mise run build` | Build the Python package. |
| `mise run check` | Run lint, tests, and build. |
| `mise run release:bump` | Bump package version and changelog. |
| `mise run release:publish` | Publish package and GHCR image. |

Useful file-scoped commands:

```sh
mise exec -- uv run pytest tests/test_file.py
mise exec -- uv run pytest tests/test_file.py::test_name
mise exec -- ruff check path/to/file.py
mise exec -- ruff format path/to/file.py
mise exec -- ty check path/to/file.py
```

## Code standards

- Keep behavior covered by tests in `tests/`.
- Prefer small, focused changes.
- Keep UI behavior and command output stable unless tests and docs are updated.
- Use type hints for new Python code.
- Let `mise run fix` handle formatting before review.
- Use generic examples only (`example.com`, `dc01.example.com`, documentation IP
  ranges). Never commit real hostnames, domains, usernames, passwords, network
  ranges, or internal notes.

## Documentation standards

Keep each document focused on its audience:

- Put user goals in `README.md`: what sambatui does, how to install/run it, how
  to configure it, and how to operate it safely.
- Put contributor goals here: setup from checkout, development tasks, tests,
  standards, pull requests, and releases.
- Put security reporting in `SECURITY.md`; do not duplicate private reporting
  details in public issue templates beyond linking to it.
- Put agent-only workflow rules in `AGENTS.md`; avoid adding agent instructions
  to user docs.

When changing behavior, update user docs only when the user-facing workflow,
configuration, command output, or security guidance changes.

## Issues

GitHub Issues are the source of truth for planned work.

- Check existing issues before starting work.
- Use `.github/ISSUE_TEMPLATE/agent_task.md` for agent-led maintenance or
  implementation work.
- Record status, scope changes, decisions, validation, and handoff notes in the
  relevant issue.
- Report vulnerabilities by following [SECURITY.md](SECURITY.md), not by opening
  a public issue.

## Commits and PRs

- Use Conventional Commits for commit messages and PR titles.
- Choose branch names that map cleanly to Conventional Commit titles.
- Run `mise run check` before opening a PR, or document why a narrower gate was
  used.
- Include concise context in the PR description: what changed, why, and how it
  was validated.
- Link the relevant issue with `Fixes #123`, `Closes #123`, or `Related to #123`.

## Releases

Bump releases with:

```sh
mise run release:bump
```

Publish releases with:

```sh
mise run release:publish
```

`mise run release:publish` also publishes the GHCR image. Release CI requires
repository secrets `DHI_USERNAME` and `DHI_PASSWORD` so GoReleaser can pull
Docker Hardened Images from `dhi.io`.
