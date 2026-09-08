# Security Policy
 
## Supported versions
 
This project doesn't have tagged releases yet, everything lives on `main`
and that's what's maintained. Once versioned releases start, this table
will track which ones still get security fixes.
 
| Version | Supported |
| ------- | --------- |
| main (2.0.x) | :white_check_mark: |
 
## Reporting a vulnerability
 
If you find a security issue, please don't open a public GitHub issue for
it. Use GitHub's private reporting instead: go to the **Security** tab on
this repository, then **Report a vulnerability**. That opens a private
advisory that only you and the maintainer can see until it's resolved.
 
Include what you can: the affected file or endpoint, steps to reproduce,
and what an attacker could actually do with it (read data, run code,
bypass the rule engine's verdict, get the LLM to follow injected
instructions from evidence text, and so on).
 
This is a solo-maintained project, not a company with a support contract,
so there's no guaranteed SLA. In practice, expect an acknowledgment
within a few days, and either a fix or an explanation of why it's out of
scope after that. If a report is accepted, I'll credit you in the fix
(unless you'd rather stay anonymous) and note it in `CHANGELOG.md`. If
it's declined, I'll explain why rather than just closing it silently.
 
A few areas worth knowing about before you report, since they're already
documented, not oversights: `THREAT_MODEL.md` lays out what this tool is
built to defend against (prompt injection from evidence text, a hijacked
local model, zip bombs, malicious attachments identified by hash) and
what it explicitly doesn't handle yet (multi-tenant auth is the main
one). If what you found is already listed there as a known gap, it's
still worth reporting, being explicit about it in writing is different
from having it actually closed.
