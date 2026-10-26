# Recorded fixtures from real machines

Drop here the JSON produced by `zerobirus scan --json --out report.json` on a real Windows
machine (already redacted and with user names replaced). The tests in
`tests/unit/test_recorded_machines.py` pick up every `*.json` file in this folder.

Currently missing on purpose: a real `Memory Compression` process (it does not exist on the
windows-latest runner). The test for it is skipped until a file containing it is added here.
See docs/WINDOWS_TEST_PLAN.md.
