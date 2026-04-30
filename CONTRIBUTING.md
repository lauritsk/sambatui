# Contributing

Thanks for improving sambatui. This project uses `mise` for tooling and task
orchestration.

## Setup

1. Install and enable `mise`.
2. Clone the repository.
3. Trust the project configuration:

```sh
mise trust
```

4. Run the full quality gate:

```sh
mise run check
```

## Development workflow

Use `mise` tasks rather than invoking tools directly:

| Task | Purpose |
| --- | --- |
| `mise run sambatui` | Run the app from checkout. |
| `mise run lint` | Run hk-managed checks. |
| `mise run fix` | Run hk-managed formatters and fixers. |
| `mise run test` | Run pytest in parallel with coverage reporting. |
| `mise run build` | Build the Python package. |
| `mise run check` | Run all project checks. |
| `mise run release:bump` | Bump package version and changelog. |
| `mise run release:publish` | Publish package and GHCR image. |

`mise run release:publish` also publishes the GHCR image. Release CI requires
repository secrets `DHI_USERNAME` and `DHI_PASSWORD` so GoReleaser can pull
Docker Hardened Images from `dhi.io`.

## Code standards

- Keep behavior covered by tests in `tests/`.
- Prefer small, focused changes.
- Keep UI behavior and command output stable unless tests/docs are updated.
- Use type hints for new Python code.
- Let `mise run fix` handle formatting before review.

## Commits and PRs

- Use Conventional Commits for commit messages and PR titles.
- Choose branch names that map cleanly to Conventional Commit titles.
- Run `mise run check` before opening a PR.
- Include concise context in the PR description: what changed, why, and how it
  was validated.

## Reporting issues

When filing bugs, include:

- sambatui version or commit SHA.
- Operating system and shell.
- Command you ran.
- Expected behavior.
- Actual behavior and relevant output.

Report security issues through the process in `SECURITY.md` instead of public
issues.
