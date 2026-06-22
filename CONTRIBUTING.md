# Contributing

Contributions must preserve evidence-based verdicts and risk-policy enforcement.

Before opening a pull request:

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src/perfektblue
pytest
```

New target profiles require documented match signals. New active modules require a target
fixture, explicit compatibility, a non-executable canary step, cleanup behavior, and tests for
vulnerable, patched, unsupported, and interrupted states.

