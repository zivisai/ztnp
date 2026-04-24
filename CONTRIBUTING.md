# Contributing to ZTNP

Thanks for your interest in helping shape the Zero-Trust Negotiation Protocol.
ZTNP is an early-stage open specification and we actively want feedback from
implementers, security researchers, MCP ecosystem builders, and agent framework
authors.

## Ways to Contribute

### 1. Review the Draft

Read [draft-zivis-ztnp-00.md](./draft-zivis-ztnp-00.md). If anything
is ambiguous, incorrect, or under-specified, open an issue. Specifically
valuable:

- **Spec ambiguities** — two implementers could reasonably interpret a
  requirement differently
- **Threat model gaps** — an adversary class or attack we missed (see
  Section 14)
- **Security considerations** — a mitigation that is weaker than stated, or
  missing
- **Interop edge cases** — cases where our normative language is too strict or
  too loose

### 2. Propose a Profile

ZTNP's base claims schema is intentionally minimal. Domain-specific claim
extensions (healthcare, finance, CI/CD, supply chain) belong in **profiles**.

If you have a specific domain in mind, open a "Profile Proposal" issue
describing:
- The domain and why a profile is needed
- Proposed claim names and semantics
- Relationship to existing compliance frameworks in that domain

### 3. Implement ZTNP

Build a Requester, Prover, or both. Report:
- What was hard to implement correctly
- Where the spec forced you to make a judgement call
- Performance observations (handshake overhead, IKS caching behavior)

Implementations — even rough prototypes — are the most valuable feedback.

### 4. Contribute Test Vectors

See [test-vectors/README.md](./test-vectors/README.md). New vectors covering
edge cases the current set misses are very welcome.

### 5. Security Research

Report suspected specification-level vulnerabilities via the process in
[SECURITY.md](./SECURITY.md). Non-sensitive spec bugs can be filed as issues.

## Issue Process

- **Bugs and ambiguities:** use the "Spec Issue" template
- **Profile proposals:** use the "Profile Proposal" template
- **Implementation feedback:** use the "Implementation Feedback" template
- **Discussion questions (no specific bug):** open a GitHub Discussion instead
  of an issue

## Pull Request Process

For small, obvious fixes (typos, broken links, reference corrections), a
direct PR is fine.

For substantive changes to the specification:

1. **Open an issue first.** Describe the proposed change and its rationale.
2. **Wait for maintainer response.** We will confirm whether the change is in
   scope, out of scope, or needs discussion.
3. **Open a PR referencing the issue.** Include:
   - A clear commit message describing *why* the change is needed
   - Updated `CHANGELOG.md`
   - Updated section(s) in the draft if any normative behavior changes
   - Updated test vectors if the change affects verification outcomes

**We will not merge substantive normative changes without prior discussion.**
This keeps the spec stable and lets the community weigh in.

## Normative vs. Editorial Changes

- **Editorial** — typos, grammar, formatting, clarifications that do not
  change normative behavior. Fast-track, squash-merge OK.
- **Normative** — changes that would cause a previously-conforming
  implementation to become non-conforming, or a previously-non-conforming one
  to become conforming. These require discussion and a new draft version.

## Authorship and Attribution

ZTNP started as ZIVIS-authored work and is being opened up for community
contribution.

- Contributors who land substantive changes will be credited in the draft's
  Revision History.
- Contributors who co-author sections, profiles, or major normative changes
  may be listed as co-authors in the Authors' Addresses section of a future
  draft version, subject to IETF policy on draft authorship (if and when the
  draft is submitted to IETF).
- By submitting a contribution, you confirm that you have the right to
  contribute it under the repository's licensing (CC-BY-4.0 for
  specification text, Apache-2.0 for code, and the IETF Trust Legal
  Provisions for any material destined for IETF submission).

## Code of Conduct

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
In short: be constructive, assume good faith, disagree on the merits, not on
the person.

Report conduct concerns to `security@zivis.ai` (also serves as the project
conduct channel for now).

## Governance

ZTNP is currently maintained by ZIVIS. As external contributors accumulate,
we intend to move to a community-governed model — likely a working group
structure within a host foundation (OpenSSF, CNCF TAG Security, or IETF).
Governance proposals are welcome.

## Questions?

- **General discussion:** GitHub Discussions
- **Specific spec issue:** GitHub Issues
- **Private / security:** security@zivis.ai
