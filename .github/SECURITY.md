# Security Policy

## Supported versions

| Version  | Supported |
| -------- | --------- |
| 0.1.0    | Yes       |
| < 0.1.0  | No        |

Security fixes ship in a new FramePrism release. Update to the latest
supported release.

## Reporting a vulnerability

Report security problems privately — do not open a public issue.

- Use the Security tab → "Report a vulnerability" (private; no public issue
  and no email exposure).
- Include: the affected version (the `frameprism --version`
  output), the reproduction steps or the failing input, and the
  observed behavior vs. the expected behavior.

We aim to acknowledge a report within 3 business days, and to ship a
fix in a new release as soon as the evidence warrants.

## A note on the offload / write paths

This tool moves media between a camera card, drives, and an archive,
and verifies every copy. Bugs in the offload, repair, and restore
paths are data-integrity issues: a defect there can affect a user's
only copy of footage. If you find a defect in these paths, report it
privately first — a public report before a fix ships helps nobody —
and keep the affected media intact (do not delete the original, do
not re-copy over it) until the fix is available.

The tool's safety posture (the refusal classes, the
verify-before-wipe gate, the durability seams) is documented in
`docs/security.md`.
