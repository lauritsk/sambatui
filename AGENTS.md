# Agent Instructions

## Package Manager

Use **uv** managed by **mise**: `mise run install`, `mise run sambatui`.

## File-Scoped Commands

| Task | Command |
|------|---------|
| Test file | `mise exec -- uv run pytest tests/test_file.py` |
| Test case | `mise exec -- uv run pytest tests/test_file.py::test_name` |
| Lint | `mise exec -- ruff check path/to/file.py` |
| Format | `mise exec -- ruff format path/to/file.py` |
| Typecheck | `mise exec -- ty check path/to/file.py` |

## Quality Gates

| Task | Command |
|------|---------|
| Fix | `mise run fix` |
| Lint | `mise run lint` |
| Test | `mise run test` |
| Check | `mise run check` |
| Bump release | `mise run release:bump` |
| Publish release | `mise run release:publish` |

## Issue Tracking

- Use GitHub Issues; check `gh issue list` before work.
- Agent tasks use `.github/ISSUE_TEMPLATE/agent_task.md`.
- Record status, decisions, scope changes, validation, and handoff in the issue.
- Security: follow `SECURITY.md`; no public issue.

## Key Conventions

- Source: `src/sambatui/`; tests: `tests/`.
- Follow setup and workflow details in `CONTRIBUTING.md`.
- Keep UI behavior and command output stable unless tests and docs change.
- Use type hints for new Python code.
- Use Conventional Commits for commits and PR titles.
- Squash merges only; no merge commits or fast-forward merges.

## Session Completion

1. Update or close the tracking issue.
2. Run an appropriate quality gate if files changed.
3. If committing: `git pull --rebase`, `git push`, `git status`.
4. Verify the branch is up to date with origin.
