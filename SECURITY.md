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
