# Contributing

Thank you for your interest in contributing.

## Guidelines

- **Authorized use only.** All contributions must relate to educational or authorized security-testing functionality.
- **No secrets.** Never commit API keys, credentials, private keys, or personal information.
- **Tests.** Add or update unit tests for any logic changes. Run `python3 -m pytest -q` before submitting.
- **Lint.** Ensure `python3 -m py_compile` passes for every `.py` file.
- **Scope.** Keep pull requests focused on a single change.
- **Disclaimers.** Preserve all legal disclaimers and authorized-use notices in README and code.

## Development Setup

```bash
# Clone and enter the repo
git clone <url> && cd <repo>

# Run tests
python3 -m pytest -q

# Syntax check
find . -name '*.py' -not -path '*/.git/*' -not -path '*__pycache__*' \
  -exec python3 -m py_compile {} \;
```

## Pull Requests

1. Fork the repository.
2. Create a feature branch (`git checkout -b fix/...`).
3. Make changes, add tests.
4. Ensure all tests pass and code compiles clean.
5. Open a PR with a clear description.

## Code of Conduct

Be respectful. Focus on security education and authorized testing.
