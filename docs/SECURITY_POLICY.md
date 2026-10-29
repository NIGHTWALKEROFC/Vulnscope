# Security and authorization policy

VulnScope is an authorized-use security assessment tool. By using it you
agree to the following:

1. **Only assess systems you own or have explicit written authorization to
   test.** Unauthorized scanning of third-party systems may be illegal in
   your jurisdiction (e.g. under the U.S. Computer Fraud and Abuse Act, the
   UK Computer Misuse Act, or similar laws elsewhere).
2. The CLI and dashboard both require an explicit authorization
   acknowledgement before a scan starts (`scan.require_ack` in
   configuration; disable only in automated pipelines you control).
3. Private, loopback and cloud-metadata network destinations are blocked by
   default (`--allow-private` opt-in) to reduce the risk of SSRF-style
   misuse against infrastructure you did not intend to touch.
4. VulnScope does not include exploitation, persistence, credential theft,
   destructive testing, or denial-of-service modules by design. Findings
   marked `potential` or `version_match` are not confirmed exploitable —
   verify manually before taking action.
5. Secrets detected during a scan (API keys, passwords, tokens) are always
   masked in reports and logs; the full value is never stored or displayed.

## Reporting a vulnerability in VulnScope itself
Please open a private security advisory on the GitHub repository (Security
tab → "Report a vulnerability") rather than a public issue, so a fix can be
prepared before details are disclosed.
