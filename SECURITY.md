# Security Policy

## Reporting Vulnerabilities in the Specification

ZTNP is an open specification. We treat specification-level vulnerabilities —
flaws that would compromise the security of any conforming implementation —
as seriously as implementation bugs.

### What counts as a specification vulnerability?

- An attack that defeats a security property the spec claims to provide (e.g.,
  a replay attack that bypasses the `bind.nonce` construction)
- An ambiguity that different implementers would reasonably resolve in
  incompatible, insecure ways
- A cryptographic construction that is weaker than the spec implies
- A threat that the spec does not name or does not adequately address

### How to report

**Preferred (coordinated disclosure):**

Email: **security@zivis.ai**

Please include:
- A clear description of the issue
- The section and paragraph of the draft it relates to
- Attack scenario or proof-of-concept (text is fine; runnable PoC is better)
- Suggested mitigation, if any
- Whether you want public acknowledgement

We will acknowledge receipt within **5 business days** and provide a substantive
response within **30 days**. Coordinated disclosure timeline is negotiable based
on severity and complexity.

**Public (non-sensitive issues):**

For specification bugs that do not require coordinated disclosure — typos,
clarifications, non-exploitable ambiguities — open a GitHub issue using the
"Spec Issue" template.

## Scope

In scope:
- The ZTNP specification itself (`draft-zivis-ztnp-*.md`)
- Reference code in `reference/` (clearly labeled as illustrative, not
  production-ready)
- Test vectors (if found to be incorrect or misleading)

Out of scope:
- ZIVIS-operated infrastructure (the ZIVIS platform, IKS endpoints, assessment
  systems). Please report those via ZIVIS's product security channel.
- Third-party implementations of ZTNP. Report to their maintainers directly.

## Acknowledgements

Researchers who responsibly disclose specification-level vulnerabilities will
be credited in the Revision History of the next draft and in `CHANGELOG.md`
unless they request anonymity.

## Scope Note on Reference Code

The code under `reference/` is intended to illustrate the specification and
help implementers validate their work against the spec's requirements. It is
**not** production-hardened. Do not deploy it as-is in a security-sensitive
environment. Production implementations should be reviewed by a qualified
security engineer and subjected to fuzz testing, key management review, and
penetration testing.

## PGP / Signal

PGP is available on request (email security@zivis.ai). We can also move to
Signal for time-sensitive coordination.
