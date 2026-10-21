# Changelog

## 1.1.0

### Fixed
- **Denial of service in the email regex.** The original pattern rescanned every
  run of word characters from each start position (quadratic): a single
  50 000-character string such as `aaaa...` or a long run of digits stalled a
  worker for ~15 s. Emails are now found by locating each `@` and expanding a
  bounded window (linear time; worst measured input is ~90 ms). Covered by a
  timing regression test.
- **PII was detected but not redacted when it was the only finding.** An email
  alone scores below the transform threshold, and the analyzer returned the
  original text for `allow`. PII is now always redacted, and any modification
  forces at least `transform`.
- **Docker UI called `/analyze/analyze`.** `docker-compose.yml` set `API_URL`
  to the full endpoint while the UI appended `/analyze` again. Compose now sets
  the base URL, and the UI/CLI accept either form.
- **`_init_.py` -> `__init__.py`** in `app/`, `app/core/`, `app/utils/` and
  `tests/` (imports only worked through implicit namespace packages).
- **Phone detection** no longer redacts order ids, ISBNs, timestamps or Aadhaar
  numbers, no longer leaves digits behind when redacting cards, and now finds
  `(415) 555-2671` style numbers.
- **Injection phrases in context documents** (e.g. a planted "ignore previous
  instructions") were never detected, because documents only ran the RAG
  patterns. Documents now run both rule sets.
- Detection and sanitization now use the same rules (previously the sanitizer
  rewrote `system:` in ordinary prompts that the detector had not flagged).
- README: stale test count, Docker screenshot rendering as a heading, wrong
  `cd` path, Windows-only line continuation in a bash block, name mix-up.

### Added
- Normalisation before matching: NFKC, invisible/format characters (incl.
  Unicode tag block), Cyrillic/Greek look-alikes, leetspeak for injection
  phrases, flexible whitespace including newlines.
- Regex rules with synonyms, plural/singular and negation handling
  (`don't forget your instructions` is not flagged).
- Base64-encoded injection payloads (one level).
- Payment-card (Luhn + issuer prefix) and Aadhaar (Verhoeff) detection.
- Per-rule severities; score = highest severity per tag + bonus per distinct
  rule (capped), so repeating a phrase no longer matters.
- Context-document quarantine for high-severity injections;
  `quarantined_doc_ids` in the response.
- `source` and `rule` on every reason; `/policy` now lists all rules.
- Input limits (prompt length, number/size of documents, unique document ids).
- JSON log lines including `app_id`, `user_id`, matched rule ids.
- `requirements.dev.txt`, `.dockerignore`, extended `.gitignore`.
- Much larger test suite (parametrised bypass / false-positive tables).

### Changed
- `requirements.api.txt` now contains runtime dependencies only (it was a full
  `pip freeze` including Streamlit, pandas, pytest...). The UI requirements are
  pinned. Docker images copy only what they need.
- Response/behaviour changes to be aware of:
  - `sanitized_context_docs` no longer contains quarantined documents.
  - A request whose only finding is PII now returns `transform` (was `allow`).
  - `reasons[]` gained `source` and `rule`; one reason per rule per source,
    with "(+N more)" for repeats.
  - `RAG_INJECTION_SCORE` / `PII_SCORE` / `PROMPT_INJECTION_SCORE` constants
    were replaced by per-rule severities in `app/core/policy.py`.
  - `detect_*` functions return `Finding` objects (not `Reason` models).
- Removed unused `DEFAULT_HOST` / `DEFAULT_PORT` from `config.py`.
