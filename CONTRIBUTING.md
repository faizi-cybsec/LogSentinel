# Contributing to LogSentinel

Contributions are welcome — especially new **MITRE ATT&CK detection rules**, **log format parsers**, and **test cases**.

## Development Setup

```bash
git clone https://github.com/faizi-cybsec/LogSentinel.git
cd LogSentinel
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Adding a Detection Rule

1. Add a new rule or append to an existing `.json` file in `rules/`.
2. Ensure every rule includes:
   - Unique `id` (e.g., `LS-AUTH-003`)
   - `title`, `description`, `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
   - `mitre_tactic` and `mitre_technique`
   - `rule_type` (`match`, `threshold`, or `sequence`)
   - `formats` (`auth`, `web`, `jsonl`, or `all`)
   - `remediation` guidance for SOC analysts
3. Validate rules and run tests:
   ```bash
   logsentinel validate-rules
   python -m unittest discover -s tests -v
   ```

## Pull Request Checklist

- [ ] All unit and integration tests pass (`python -m unittest discover -s tests -v`)
- [ ] New rules pass `logsentinel validate-rules`
- [ ] Sample log lines or unit tests are included for new detections/parsers
- [ ] Documentation (`README.md`) is updated if CLI flags or rule formats change
