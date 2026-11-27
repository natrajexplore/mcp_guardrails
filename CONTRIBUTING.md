# Contributing to MCP Guardrail Gateway

Thanks for helping. Issues and pull requests are welcome.

## Reporting bugs and requesting features
- Search existing [issues](https://github.com/natrajexplore/mcp_guardrails/issues) first.
- For bugs include: version (`guardrail version`), Python version, steps to
  reproduce, expected vs actual behaviour, and redacted config/snapshot excerpts. **Never paste tokens, passwords or
  production device data.**
- Security problems: follow [SECURITY.md](SECURITY.md), not a public issue.

## Development setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q -p no:asyncio
ruff check src tests && ruff format --check src tests
```

## Pull requests
1. Fork, create a branch from `main` (`feature/<short-name>` or `fix/<short-name>`).
2. Add or update tests for every behaviour change; keep the suite green and `ruff` clean.
3. Update README/docs and `CHANGELOG.md` (Unreleased section).
4. Keep PRs focused; describe the problem, the change and how you tested it.
5. By contributing you agree your contribution is licensed under the Apache License 2.0.

## Design principles
- **Fail safe**: unknown means deny/write/high-risk, never the permissive option.
- **Deterministic and explainable**: every decision must be traceable to a policy rule and an audit record. No LLM
  inside the gateway.
- **Never weaken an invariant**: the security invariants in [AGENTS.md](AGENTS.md) apply to human contributors too.
- **No secrets at rest**: tokens are stored as SHA-256 digests; secrets are redacted from logs.
