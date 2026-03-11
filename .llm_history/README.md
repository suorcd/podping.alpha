# .llm_history

This directory tracks AI-assisted changes in a consistent, lightweight format.

## Rules

1. Store all entries in `.llm_history/entries/`.
2. Each entry file is named `YYYY-MM-DD.md`.
3. One entry per day. Append new work to the existing file for that date.
4. Keep entries concise and factual.
5. Use plain Markdown with short sections and bullets.
6. Do not include secrets, credentials, or private data.
7. Reference files with repo-relative paths in backticks.
8. Prefer ASCII text only.

## Entry Template

```
# YYYY-MM-DD

## Summary
- ...

## Files Changed
- `path/to/file`

## Notes
- ...
```
