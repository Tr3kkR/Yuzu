- Raised the always-loaded instruction-file budget from 32,000 to 40,000 characters
  (`tests/test_issue_docs.py`, `docs/instruction-file-standard.md`), and the hard cap from 40,000 to
  48,000 in step so the budget keeps its original runway rather than becoming the wall itself.
  `.claude/routed-concerns.md` had reached 31,929 of 32,000 characters with new rows still owed from
  upcoming plugin work, each prior breach having cost an unplanned scramble PR to split further —
  splitting is exhausted (`docs/instruction-file-standard.md`), so the budget moves instead.
