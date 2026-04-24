# Changelog

All notable changes to the ZTNP specification and this repository are recorded
here. Changes to the normative specification are also reflected in the draft's
own Revision History table.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates are ISO 8601. Repository-level changes (CI, docs, reference code) are
tracked here even when the draft itself does not change.

## [Unreleased]

### Changed
- **Binding mode codes renamed** to PA-R, PA-C, PA-O, parallelling the
  Posture Assertion primitive. The `Mutual` mode name is unchanged.
- **Appendix D rewritten** as a generic Profile Extension Mechanism
  (informative). Vendor-specific profile content has been removed from the
  specification; profiles are defined as independently-published
  extensions outside this repository.
- **In-body vendor-specific profile references** removed from §1.3, §8.3,
  and §14.5. Replaced with generic "profile" references pointing at the
  rewritten Appendix D.
- **Example URLs** in Appendix A, B, and C changed from a vendor-specific
  URL to `https://issuer.example` (IANA-reserved example domain) so the
  normative examples do not imply any specific issuer.
- **Authors' Addresses** now lists Jake Miller (ZIVIS) as the individual
  author, per IETF convention that drafts list named humans rather than
  only an organization.

### Added
- **§17 Enrollment** — optional-but-normative section defining how a new
  Prover obtains its first Posture Assertion. Closes the gap between "agent
  exists" and "agent has verifiable posture" that matters most in agentic AI
  deployments where agents are instantiated dynamically.
  - §17.1 Parties: Enrollee, Issuer, Endorser (the latter is the root
    principal from §16.1.2).
  - §17.2 Flow: ENROLL_INIT → ENROLL_CHALLENGE → ENROLL_REQUEST →
    ENROLL_RESULT.
  - §17.3 Request fields incl. `subject_kind`, `subject_metadata`,
    `subject_key`, `challenge_sig`, `endorsement`, `evidence_refs`,
    `proposed_sub`.
  - §17.4 Result fields: assigned `sub`, first Posture Assertion, IKS URL,
    renewal hint.
  - §17.5 Two modes: **Self-Enrollment** (no endorsement, `tier <= 1`) vs.
    **Assessed Enrollment** (endorsement required, any tier).
  - §17.6 Enrollment anchors: orchestrator, human (WebAuthn-style), CI/CD
    (SPIFFE/OIDC workload federation).
  - §17.7 **RFC 7591 Compatibility Profile**: mapping ZTNP enrollment to
    OAuth 2.0 Dynamic Client Registration Protocol; RFC 7592 for updates
    and deletions.
  - §17.8 HTTP transport binding at `/.well-known/ztnp-enroll/*`.
  - §17.9 Enrollment-specific security considerations (endorsement forgery,
    Sybil, replay, subject hijacking, revocation linkage, cross-profile
    tier confusion).
- Seven new denial reason codes: `ENROLL_CHALLENGE_INVALID`,
  `ENROLL_SIG_INVALID`, `ENROLL_ENDORSEMENT_MISSING`,
  `ENROLL_ENDORSEMENT_INVALID`, `ENROLL_SUBJECT_COLLISION`,
  `ENROLL_ASSESSMENT_FAILED`, `ENROLL_TIER_EXCEEDED`.
- New IANA registry: **ZTNP Enrollment Mode Registry** with initial values
  `self`, `assessed`.
- New Well-Known URI registration: `ztnp-enroll`.
- RFC 7591 (OAuth 2.0 Dynamic Client Registration) and RFC 7592
  (Management Protocol) added as informative references.
- Optional Enrollment conformance checklist added to §19.
- **§16 Agentic AI Extensions** — optional section addressing security properties
  specific to multi-agent delegation chains:
  - §16.1 Delegation Chain Attestation: nested JWS structure where each
    delegating principal wraps and signs the previous layer; root layer is a
    user/orchestrator-signed Intent object; scope monotonicity is enforced
    (child layers cannot expand scope beyond parent).
  - §16.2 Intent-Scoped Permits: extends the Permit format with `intent_hash`,
    `intent_scope`, `chain_root_iss`, and `chain_root_jti` fields; Requesters
    MUST deny operations outside `intent_scope` even if `constraints` allow them.
  - §16.3 Behavioral Claim Extensions: `claims.posture.ai_behavior` sub-object
    with claims including `prompt_injection_tested`, `tool_call_audit_logged`,
    `tool_misuse_score`, `output_validated`, `human_in_loop_policy`,
    `max_tool_call_depth`, `data_exfil_controls`.
- **§12.2 Proof-of-Possession (PoP) Binding** — DPoP-style [RFC9449] mechanism
  for binding Permits to an ephemeral Prover key pair. Prevents bearer Permit
  theft and cross-session replay. Adds `cnf.jkt` field to Permit format.
- **§12.3 Channel Binding** — TLS channel binding via `tls-exporter` [RFC9266]
  that ties a Permit to the specific TLS session in which it was negotiated.
  Prevents cross-connection attacks. Adds `ch_binding` field to Permit format.
- **§15.11** — Prompt injection and instruction integrity consideration for
  agentic AI deployments; references §16.2 Intent-Scoped Permits as mitigation.
- **New denial reason codes**: `DEL_CHAIN_MISSING`, `DEL_CHAIN_BROKEN`,
  `DEL_CHAIN_SCOPE_EXPANDED`, `DEL_CHAIN_EXPIRED`, `DEL_CHAIN_UNTRUSTED_ROOT`,
  `INTENT_SCOPE_MISMATCH`.
- RFC 9449 (DPoP) and RFC 9266 (channel bindings for TLS 1.3) added to
  normative references.
- Threat Model section (draft §14) with adversaries, assumptions, assets, and
  attack-surface table
- `LICENSE`, `LICENSE-SPEC` (CC-BY-4.0), `LICENSE-CODE` (Apache-2.0)
- `SECURITY.md` with coordinated disclosure process
- `CONTRIBUTING.md` with issue/PR guidance
- GitHub issue templates: spec issue, implementation feedback, profile proposal
- `test-vectors/` with 7 template vectors covering valid mark, expired,
  bad signature, bad binding, wrong subject, unknown kid, and tier-without-issuer
- `reference/ts/` TypeScript reference verifier (ES256 via `jose`)
- Informative references to SCITT architecture draft and GNAP (RFC 9635)

### Changed
- **Renamed "Trust Mark" → "Posture Assertion" (PA)** throughout the spec,
  README, reference code, and test-vector documentation. "Trust Mark" was
  ZIVIS-flavored marketing language; the IETF draft should use vendor-neutral
  terminology. The wire field name `trust_mark` and reason code prefix `TM_*`
  are retained as interface-level identifiers (see §8 terminology note) to
  avoid gratuitous wire-format churn in a -00 draft.
- **§15.8 Confused Deputy** strengthened: added PoP binding, channel binding,
  and delegation chain integrity as the three implementation-level defenses;
  connected to §12.2, §12.3, and §16.1 respectively.
- **§12 Permit Format** restructured into §12.1 Required Fields, §12.2 PoP
  Binding, §12.3 Channel Binding.
- **§18 Conformance** extended with optional agentic, PoP, and channel binding
  checklists.
- **§17.2 IANA — ZTNP Denial Reason Code Registry** updated with six new
  codes for delegation chain and intent scope failures.
- Renumbered §§17–22 to accommodate §16 Agentic AI Extensions.
- **Renamed draft from `draft-zivis-rats-ztnp-00` to `draft-zivis-ztnp-00`.**
  The `-rats-` WG hint in the filename presumed RATS WG ownership before the
  community has weighed in. The new name is WG-neutral and appropriate for an
  individual submission.
- **Rewrote §5 as "Relationship to Existing IETF Work"** comparing RATS, SCITT,
  OAuth/GNAP, and JOSE/COSE honestly. Previously §5 claimed ZTNP was a RATS
  profile; on reflection, RATS is hardware-attestation-centric and SCITT is
  its own protocol (with a Transparency Service, Receipts, and a wire
  protocol) rather than a framework — so claiming to be a profile of either
  overstated the relationship. The new framing describes composition and
  compatibility without presuming a WG venue. §5.5 explicitly asks the
  community which WG is the right home.
- Moved RFC 9334 (RATS) from normative to informative references, reflecting
  that ZTNP does not require RATS conformance.
- Renumbered sections 14–20 → 15–21 to accommodate the new Threat Model
  section (this entry carries over from the earlier pass).

## [draft-zivis-rats-ztnp-00] — 2026-04-15

### Added
- Initial IETF Internet-Draft formatting (header, Status of This Memo, BCP 78/79 boilerplate)
- Bidirectional Trust Binding Modes: PA-R (Resource-Presents), PA-C (Caller-Presents), Mutual, PA-O (Opportunistic)
- Relationship to IETF RATS (RFC 9334) — explicit role mapping
- Normative HTTP transport binding (§13.1)
- Expanded MCP binding with `nonce_sig` specification (§13.2)
- IANA Considerations with 4 registry requests (§16)
- Normative and Informative References (§19, §20)
- Authors' Addresses (§21)
- DENY reason codes table (§10.3)
- Tier issuer-anchoring clarification (§8.3 and §11): tier values are profile-defined and tier_min policies MUST be paired with an issuers constraint

### Changed
- Protocol flow diagram now shows Mutual binding as the full case
- Verification failure reasons are now structured reason codes rather than free-form strings

## [0.1.0-internal] — 2026-02-20

Initial internal draft. Not released.
