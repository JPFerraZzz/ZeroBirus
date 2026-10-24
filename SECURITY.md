# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (private vulnerability reporting). Do not open a public issue for security problems.

Include what you found, how to reproduce it, and which version or commit is affected. Expect a first reply within a few days.

## Scope

ZeroBirus is a malware removal tool, so the most relevant problems are:

- a way to make it touch protected paths or processes (Windows files, antivirus);
- a way to make it act outside the authorised plan;
- execution or evaluation of data read from the system;
- secrets showing up in output, logs or reports.

## Supported versions

There is no release yet. Only the `main` branch is supported.

## Do not send malware

Do not attach real malware samples to reports. A description, a hash or a synthetic reproduction is enough.

## Known limitations

- **Redaction of bare hex keys.** `core/redact.py` keeps hex strings of exactly 32, 40 and 64 characters visible, because they are file hashes (MD5, SHA-1, SHA-256) that reports must show so users can look them up elsewhere. A secret that is a bare 64-character hex string, with no name next to it (`key=`, `token=`, `password=`, `--api-key` and similar), is therefore not redacted. Secrets with a name, longer hex blobs, long base64 blobs, wallet addresses and URL credentials are redacted.
