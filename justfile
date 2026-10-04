set dotenv-load
set positional-arguments

# List available recipes.
default:
    @just --list

# Install project and development dependencies.
setup:
    uv sync

# Check Python and Markdown formatting and style.
lint:
    uvx ruff check .
    uvx ruff format --check .
    uvx rumdl check README.md

# Run the test suite.
test *args:
    uv run pytest "$@"

# Run all checks.
check: lint test

# Run sambatui with variables from .env.
run *args:
    uv run sambatui "$@"

# Build source and wheel distributions.
build:
    uv build
