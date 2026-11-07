# Contributing

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\python.exe -m ...
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
python tools/evaluate.py
```

- **Standard library only for the package.** `cryptography` is for tests and tools.
- **A new finding** goes in `src/tlswatch/checks.py`, in the table in [docs/grading.md](docs/grading.md), and gets a test in `tests/test_checks.py` and, if it comes from a handshake, a local-server scenario in `tests/test_probe.py` and `tools/evaluate.py`.
- **Anything that reads bytes from a server must refuse malformed input with `DerError` / `StarttlsError`**, never raise something else. Add the malformed case to the tests.
- **Report what could not be tested as such.** A probe the local OpenSSL cannot run is `untestable`, never "not accepted".
- Tests build their own certificates; do not commit certificates or keys.
