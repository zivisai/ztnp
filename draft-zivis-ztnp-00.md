```
Internet-Draft                                             ZIVIS
draft-zivis-ztnp-00                                        April 2026
Intended Status: Standards Track
Expires: October 2026
```

# Zero-Trust Negotiation Protocol (ZTNP)

**draft-zivis-ztnp-00**

## Abstract

The Zero-Trust Negotiation Protocol (ZTNP) is a cryptographically verifiable protocol that enables agent-to-agent and agent-to-tool trust negotiation in agentic AI systems. ZTNP covers the full trust lifecycle: enrollment (how a Prover obtains its first Posture Assertion from an Issuer), negotiation (how parties exchange and bind Posture Assertions at session establishment), and validation (how a receiving party verifies, evaluates policy, and issues scoped Permits). The specification defines message flows, a canonical claims schema, verification requirements, a policy evaluation model, optional delegation-chain attestation and intent-scoped Permits for multi-agent orchestration, and normative transport bindings for HTTP and MCP (Model Context Protocol). ZTNP composes with existing IETF work on attestation (RATS), signed statements (SCITT), scoped authorization (OAuth/GNAP), dynamic registration (RFC 7591/7592), and proof-of-possession (DPoP) without claiming to be a profile of any one of them; see Section 5. This draft is an individual submission; the appropriate IETF venue for progressing this work is an open question the authors ask the community to help answer.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force (IETF). Note that other groups may also distribute working documents as Internet-Drafts. The list of current Internet-Drafts is at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as "work in progress."

This Internet-Draft will expire on October 2026.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document.

---

## Table of Contents

1. Introduction
2. Goals
3. Non-Goals
4. Terminology
5. Relationship to Existing IETF Work
   - 5.1 IETF RATS (RFC 9334)
   - 5.2 IETF SCITT
   - 5.3 OAuth 2.0 / GNAP
   - 5.4 JOSE / COSE
   - 5.5 Positioning and WG Venue
6. Trust Binding Modes
7. Protocol Overview
8. Posture Assertion Format
   - 8.1 Required Claims
   - 8.2 Scope
   - 8.3 Claims
   - 8.4 Challenge Binding
9. Key Discovery and Verification
   - 9.1 Issuer Key Set
   - 9.2 Algorithm Agility
10. Negotiation Messages
    - 10.1 Discovery
    - 10.2 Challenge
    - 10.3 Decision
11. Policy Model
    - 11.1 Policy Inputs
    - 11.2 Policy Output
    - 11.3 Standard Constraint Types
12. Permit Format
    - 12.1 Required Fields
    - 12.2 Proof-of-Possession (PoP) Binding
    - 12.3 Channel Binding
13. Transport Bindings
    - 13.1 HTTP Binding (Normative)
    - 13.2 MCP Binding (Normative)
14. Threat Model
    - 14.1 Assumptions
    - 14.2 Adversaries
    - 14.3 Assets
    - 14.4 Attack Surface and Mitigations
    - 14.5 Out of Scope
15. Security Considerations
16. Agentic AI Extensions
    - 16.1 Delegation Chain Attestation
    - 16.2 Intent-Scoped Permits
    - 16.3 Behavioral Claim Extensions
17. Enrollment
    - 17.1 Enrollment Parties
    - 17.2 Enrollment Flow
    - 17.3 ENROLL_REQUEST Fields
    - 17.4 ENROLL_RESULT Fields
    - 17.5 Self-Enrollment vs. Assessed Enrollment
    - 17.6 Enrollment Anchors and Bootstrap
    - 17.7 RFC 7591 Compatibility Profile
    - 17.8 Enrollment Transport Binding (HTTP)
    - 17.9 Enrollment Security Considerations
18. IANA Considerations
19. Conformance
20. Versioning
21. Normative References
22. Informative References
23. Authors' Addresses

Appendix A — Example Policy
Appendix B — Example Flow (MCP)
Appendix C — Example Posture Assertion Payload
Appendix D — Profile Extension Mechanism (Informative)

---

## 1. Introduction

The rapid proliferation of autonomous AI agents and agentic tool ecosystems has introduced a class of security problem that existing identity and access management protocols do not address: how should one agent or AI system decide whether to trust another before exchanging data or invoking shared capabilities?

Existing protocols establish *who* a party is (identity) but not *how trustworthy* that party is at the time of the request (posture). A service may present a valid TLS certificate and still have unpatched critical vulnerabilities, active security incidents, or no AI governance controls whatsoever.

ZTNP addresses this gap. It defines a protocol by which any two parties in an agentic system — whether AI agents, tool servers, orchestrators, or hybrid human-agent services — can negotiate trust at session establishment time based on cryptographically signed, machine-readable security posture claims.

ZTNP is intentionally minimal at its base layer. It defines the handshake mechanics, token structure, and verification requirements. Domain-specific semantics (e.g., AI framework compliance scores, vulnerability tiering, healthcare or financial-services posture) are delegated to separately-published profiles. See Appendix D for the profile extension mechanism.

### 1.1 Motivation

The Model Context Protocol (MCP) and similar agentic tool frameworks define *how* agents call tools but define no trust model for *whether* they should. Any MCP client can call any MCP server that accepts its connection. ZTNP provides the missing trust negotiation layer.

Similar gaps exist in multi-agent orchestration frameworks, AI pipeline systems, and enterprise LLM deployments where agents dynamically discover and invoke each other's capabilities.

### 1.2 Design Philosophy

ZTNP is designed to be:

- **Layered** — a small, mandatory core (enrollment, negotiation, validation) with clearly-optional extensions (delegation chains, intent-scoped Permits, PoP, channel binding, RFC 7591 compatibility) that deployments add only as their threat model requires
- **Transport-agnostic** — the same protocol semantics apply over HTTP, WebSocket, gRPC, or MCP
- **Cryptographically verifiable** — all trust claims are signed; verification is deterministic and local at runtime (no dial-home to a central authority during negotiation)
- **Policy-local** — Requesters apply their own policies; there is no mandatory central policy authority
- **Incrementally adoptable** — systems that cannot yet provide a Posture Assertion can be treated gracefully via opportunistic binding (Section 6.4); deployments can start with negotiation-only and adopt §16/§17 as needed

Negotiation adds one round-trip to session establishment. Enrollment happens once per Prover, out-of-band from the session path. Validation is per-request but local. The protocol is not "lightweight" in total surface area — the full specification addresses a broad threat model — but its runtime cost on a per-session basis is bounded and predictable.

---

## 2. Goals

ZTNP is designed to:

1. Allow any party to verify another party's trust posture at time T.
2. Prevent replay via challenge binding.
3. Enable local, deterministic policy evaluation without calling a central authority (except optional revocation).
4. Support constrained authorization ("Permits") for follow-on actions and data sharing.
5. Interoperate across implementations and ecosystems.
6. Support bidirectional and mutual trust negotiation.

---

## 3. Non-Goals

ZTNP does not define:

- How trust posture is computed (scoring pipelines, evidence collection, assessment methodology).
- A universal risk taxonomy (profiles MAY define additional semantics).
- A mandatory transparency ledger (OPTIONAL).
- A single credential format beyond minimal normative requirements.
- Authentication or identity (ZTNP is complementary to, not a replacement for, identity protocols such as OAuth 2.0 or SPIFFE).

---

## 4. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC2119].

| Term | Definition |
|------|------------|
| **Requester (R)** | The party that initiates trust negotiation and wishes to verify another party's posture. |
| **Prover (P)** | The party that presents a Posture Assertion to demonstrate its security posture. |
| **Issuer (I)** | The entity that signs Posture Assertions (e.g., a security assessor or attestation service). |
| **Posture Assertion (PA)** | A signed token containing machine-readable security posture claims about a Prover. |
| **Policy** | Rules defined by R to decide if P is acceptable and under what constraints. |
| **Permit** | A short-lived authorization artifact issued by R to P after successful negotiation. |
| **Freshness** | The maximum allowed age since issuance of a Posture Assertion. |
| **Challenge** | A nonce generated by R for anti-replay binding. |
| **Binding Mode** | The direction(s) in which Posture Assertions are exchanged (see Section 6). |
| **IKS** | Issuer Key Set — the public key endpoint published by an Issuer. |

---

## 5. Relationship to Existing IETF Work

ZTNP draws on and composes with several existing or in-progress IETF specifications but does not claim to be a profile of any single one. This section describes each relationship honestly so that Working Group chairs, reviewers, and implementers can assess the correct venue for progressing this work.

### 5.1 IETF RATS (RFC 9334)

The RATS (Remote ATtestation procedureS) architecture [RFC9334] defines an abstract framework for remote attestation with three roles: Attester, Verifier, and Relying Party. ZTNP's Prover, Verifier, and Requester roles map onto these abstractly:

| RATS Role | Analogous ZTNP Concept |
|-----------|------------------------|
| Attester | Prover (P) |
| Verifier | ZTNP verification function |
| Relying Party | Requester (R) |
| Evidence | Posture Assertion payload + challenge binding |
| Attestation Result | ZTNP policy Decision + optional Permit |

The architectural mapping is real, but RATS was developed primarily for hardware and firmware attestation — TPM measurements, TEE quotes, confidential computing reports. ZTNP attests software-layer security posture derived from an assessment process (human review, automated testing, compliance audit). This is a different class of evidence than RATS was designed for. ZTNP is architecturally RATS-shaped but does not claim to be a RATS profile in the strict sense; readers familiar with RATS may find the role mapping above a useful mental model.

### 5.2 IETF SCITT

The SCITT (Supply Chain Integrity, Transparency, and Trust) architecture defines a system for signing, registering, and transparently logging Signed Statements about supply-chain artifacts, using COSE_Sign1 statements, a Transparency Service, and Receipts as cryptographic proofs of inclusion.

A ZTNP Posture Assertion is conceptually similar to a SCITT Signed Statement: an Issuer-signed credential about a subject. The two models are complementary:

- A Posture Assertion MAY be encoded as a SCITT-compatible COSE_Sign1 Signed Statement.
- A Posture Assertion MAY be additionally registered with a SCITT Transparency Service to provide auditable, tamper-evident history of issuance.
- A future profile of ZTNP MAY mandate SCITT compatibility for deployments that require transparency and public auditability of posture credentials.

However, ZTNP does not require a Transparency Service, does not define Receipts, and its core contribution — the real-time, challenge-bound negotiation and Permit-issuance protocol — is not addressed by SCITT. ZTNP and SCITT are complementary, not derivative; neither is a profile of the other.

### 5.3 OAuth 2.0 and GNAP

The OAuth 2.0 Authorization Framework [RFC6749] and the Grant Negotiation and Authorization Protocol (GNAP) address scoped authorization and grant negotiation. ZTNP's Permit construct (Section 12) resembles an OAuth access token or a GNAP grant: a short-lived, scoped authorization artifact issued after successful negotiation.

ZTNP differs in what the grant is based on — verified security posture rather than user consent, client authentication, or delegation. A ZTNP deployment MAY use a GNAP-compatible grant format for its Permits where that improves integration with existing authorization infrastructure.

ZTNP is not an identity or authentication protocol. It is complementary to OAuth/OIDC, mTLS, SPIFFE, and similar identity mechanisms (Section 3 non-goals).

### 5.4 JOSE / COSE

ZTNP Posture Assertions and Permits are signed tokens. The specification is algorithm-agnostic (Section 9.2) and is compatible with:

- JWS envelopes [RFC7515] over JSON payloads
- COSE envelopes [RFC9052] over CBOR payloads

Implementations that choose COSE gain direct compatibility with SCITT Signed Statements (Section 5.2). Implementations that choose JWS gain broad ecosystem tooling compatibility. Both are permitted.

### 5.5 Positioning and WG Venue

ZTNP defines a negotiation protocol (challenge → verify → permit) for contexts where signed posture credentials exist but the question of *how to use them during a live session* is not addressed by any existing IETF work. It is intentionally factored to compose with — rather than replace — adjacent protocols.

The correct IETF venue for progressing this work is an open question. Plausible candidates:

- **RATS** — if the WG views agent posture as within the scope of its attestation architecture
- **SCITT** — if the WG views ZTNP as a negotiation protocol over SCITT Signed Statements
- **OAuth / GNAP** — if the WG views Posture Assertion + Permit as a posture-gated grant mechanism
- **SAAG-routed new work** — if the Security Area Advisory Group concludes this is genuinely new territory warranting a dedicated WG or individual-submission path

The authors have deliberately not presumed a venue in this `-00` submission. Community guidance on the right home is explicitly welcomed.

---

## 6. Trust Binding Modes

ZTNP supports four Trust Binding Modes. Implementations MUST declare which modes they support in the Discovery response (Section 10.1).

### 6.1 Resource-Presents (PA-R)

The Prover presents its Posture Assertion to the Requester before any capability is invoked. The Requester decides whether to proceed.

```
Requester (R)             Prover / Resource (P)
     |                           |
     |-- "provide your PA" ----->|
     |<-- Posture Assertion ------------|
     | [verify + evaluate]       |
     | if invalid: log / skip    |
     |-- tool calls ------------>|
```

**Primary use case:** An AI agent verifying an MCP tool server before calling its tools. Analogous to TLS server certificate verification.

**Default behavior when PA unavailable:** R MAY continue with logged warning (see Section 6.4, Opportunistic mode) or MUST deny, per local policy.

### 6.2 Caller-Presents (PA-C)

The Requester presents its Posture Assertion to the Prover. The Prover decides whether to serve the request.

```
Requester (R)             Prover / Resource (P)
     |                           |
     |-- PA + request ---------->|
     |           [verify policy] |
     |<-- result or 403 ---------|
```

**Primary use case:** A sensitive MCP tool server gating access to callers that have been independently assessed. Analogous to mTLS client certificate verification.

### 6.3 Mutual (ZTNP Full Handshake)

Both parties exchange and verify Posture Assertions before proceeding.

```
Requester (R)             Prover (P)
     |                           |
     |-- "provide your PA" ----->|
     |<-- P's Posture Assertion --------|
     | [R verifies P's PA]       |
     |-- R's PA + request ------>|
     |           [P verifies R's PA]
     |<-- permit + result --------|
```

**Primary use case:** High-value agent-to-agent collaboration; cross-organization data sharing; orchestrators delegating to sub-agents.

### 6.4 Opportunistic (PA-O)

The Requester requests a Posture Assertion, validates it if present, logs its absence, and continues regardless. This mode enables progressive adoption where not all services have been assessed.

**Behavior:**
- If PA present and valid: R records posture metadata, continues.
- If PA present and invalid: R logs failure, MAY continue or deny per policy.
- If PA absent: R logs absence, continues.

**Primary use case:** Early-adoption environments; internal tooling where enforcement is aspirational but not yet mandatory.

---

## 7. Protocol Overview

ZTNP negotiation consists of three phases, shown here for the Mutual mode (Section 6.3). Simpler modes use a subset of these phases.

```
┌─────────────┐                           ┌─────────────┐
│  Requester  │                           │   Prover    │
│     (R)     │                           │     (P)     │
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │  1. DISCOVER ───────────────────────►   │
       │  ◄─────────────────── DISCOVER_RESPONSE │
       │                                         │
       │  2. CHALLENGE (nonce) ──────────────►   │
       │  ◄───────────────────── PROOF (PA)      │
       │                                         │
       │  3. [verify signature]                  │
       │     [evaluate policy]                   │
       │     [check freshness + flags]           │
       │                                         │
       │  4. PERMIT (constraints) ───────────►   │  (if allow)
       │     or DENY (reasons) ──────────────►   │  (if deny)
       │                                         │
       │  5. [subsequent tool calls with Permit] │
```

1. **Discovery:** R learns P's ZTNP capabilities, supported binding modes, and Issuer key metadata.
2. **Challenge-Response:** R issues a challenge nonce; P returns a challenge-bound, signed Posture Assertion.
3. **Verification & Policy:** R verifies the Posture Assertion signature, checks freshness and claims, and evaluates local policy.
4. **Decision & Permit:** R issues a Permit (optional, with constraints) or returns a DENY with machine-readable reasons.
5. **Authorized Calls:** Subsequent calls carry the Permit, enabling the Prover to enforce scoped constraints.

---

## 8. Posture Assertion Format

ZTNP supports any signed token format satisfying the requirements below. Implementations SHOULD use JWS [RFC7515] or COSE [RFC9052] for compactness. JSON encoding is used throughout this specification for clarity.

> **Terminology note:** The JSON wire field carrying a Posture Assertion in ZTNP messages is named `trust_mark` (see Sections 10.2, 13.1, 13.2). The field name is retained for continuity with the -00 wire format and because "mark" in JSON field nomenclature is shorter than "posture_assertion". The abstract concept is the Posture Assertion; the concrete serialization field is `trust_mark`. Similarly, denial reason codes use the `TM_` prefix (e.g., `TM_MISSING`) as wire-level identifiers. These are interface artifacts and are not intended as vendor-specific branding.

### 8.1 Required Claims

A Posture Assertion payload MUST include:

| Claim | Type | Description |
|-------|------|-------------|
| `ver` | string | Posture Assertion version (e.g., `"0.1"`) |
| `iss` | string | Issuer identifier (stable URI or DID) |
| `sub` | string | Subject identifier for the Prover |
| `iat` | int | Issued-at time, Unix seconds |
| `exp` | int | Expiration time, Unix seconds |
| `jti` | string | Unique Posture Assertion identifier (globally unique, nonce-safe) |
| `scope` | object | What this mark covers (see 8.2) |
| `claims` | object | Machine-readable posture claims (see 8.3) |
| `bind` | object | Challenge binding data (see 8.4); REQUIRED unless mode is PA-R pre-fetch |

### 8.2 Scope

`scope` MUST include:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | string | Yes | One of: `agent`, `service`, `tool`, `model`, `environment` |
| `target` | string | Yes | Canonical identifier of the subject instance (URL, name, ARN, DID) |
| `env` | string | No | Environment label (e.g., `prod`, `staging`) |
| `components` | array | No | Component identifiers covered by this mark |

### 8.3 Claims

ZTNP defines a minimal claim surface for base interoperability. Profiles MAY extend these.

`claims` MUST include:

| Field | Type | Description |
|-------|------|-------------|
| `tier` | int | Integer 0–4 (0 = unknown, 1–4 = increasing assurance); semantics are issuer-profile-defined (see note below) |
| `posture` | object | Flexible, profile-defined key-values |
| `flags` | object | Boolean flags for critical gating (see below) |

> **Tier semantics are issuer-anchored.** The 0–4 scale provides a common policy shorthand, but the precise criteria for each level are defined by the issuing authority's profile (see Appendix D for the profile extension mechanism). A `tier` value from Issuer A is not directly comparable to the same value from Issuer B unless both issuers publish equivalent tier definitions. Requesters MUST NOT apply `tier`-based policy constraints without also constraining the `issuers` field to a trusted set whose tier semantics are known. A policy specifying `tier_min` with no `issuers` constraint is incomplete and SHOULD be rejected by conforming policy engines.

`flags` SHOULD include, if applicable:

| Flag | Type | Description |
|------|------|-------------|
| `critical_open` | bool | Has open critical vulnerabilities |
| `incident_open` | bool | Has active security incident |
| `pii_access_allowed` | bool | Assessed as safe for PII access |
| `secrets_access_allowed` | bool | Assessed as safe for secrets access |
| `code_exec_allowed` | bool | Assessed as safe for code execution |

> **Note:** Profiles (Appendix D) MAY define additional structured claims (e.g., per-framework scores, domain-specific breakdowns). Base ZTNP does not mandate them.

### 8.4 Challenge Binding

To prevent replay attacks, Posture Assertions issued during a ZTNP Challenge-Response exchange MUST be bound to the Requester's challenge nonce.

`bind` MUST include:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | Yes | `nonce_hash` or `nonce_sig` |
| `nonce` | string | Yes | Hashed or plaintext challenge nonce (see below) |
| `ctx` | string | No | Session context string (e.g., `"mcp"`, `"http"`) |
| `aud` | string | No | Requester identifier |

Two binding methods are defined:

#### A) `nonce_hash` (REQUIRED to implement)

`bind.nonce` MUST be `base64url(SHA-256(challenge_nonce || ctx || aud))` where `||` denotes concatenation of UTF-8 encoded strings. The Posture Assertion signature covers the entire payload including `bind.nonce`, ensuring the binding is cryptographically committed.

Verification: R recomputes `base64url(SHA-256(challenge_nonce || ctx || aud))` and compares to `bind.nonce`. If they do not match, the Posture Assertion MUST be rejected.

#### B) `nonce_sig` (OPTIONAL)

Used when the Issuer signs Posture Assertions offline (batch issuance) and runtime challenge binding must be performed by the Prover's own key rather than the Issuer's key.

- `bind.nonce` contains the plaintext `challenge_nonce`
- The Prover additionally returns a detached signature `binding_sig` over the concatenation `(challenge_nonce || jti || sub)` using a key whose public component is either embedded in the Posture Assertion or discoverable from the subject's published key set
- The `binding_sig` is returned alongside the Posture Assertion in the PROOF message (Section 10.2)

Verification: R verifies the Posture Assertion signature (Issuer key), then separately verifies `binding_sig` against the Prover's subject key. Both verifications MUST pass.

**Conformance:** Implementations MUST support `nonce_hash`. Implementations MAY support `nonce_sig`.

**Pre-fetched Posture Assertions (PA-R mode):** When operating in Resource-Presents mode (Section 6.1), a Prover MAY serve a recently-issued Posture Assertion that was not bound to a specific challenge. In this case, the `bind` field MAY be omitted. Requesters MUST apply stricter freshness requirements when `bind` is absent (RECOMMENDED: maximum age 1 hour).

---

## 9. Key Discovery and Verification

### 9.1 Issuer Key Set (IKS)

Issuers MUST publish a key set endpoint containing active public keys and metadata. This endpoint is called the Issuer Key Set (IKS) and is analogous to a JWKS endpoint [RFC7517].

IKS MUST provide:

- Issuer identifier (`iss`) matching the value used in Posture Assertions
- Key IDs (`kid`) for each key
- Algorithm identifiers for each key
- Public key material
- Key validity windows and rotation schedule (RECOMMENDED)

Requesters MUST verify Posture Assertion signatures using keys from the IKS corresponding to the `iss` claim. Requesters MUST cache IKS responses with an appropriate TTL and MUST handle key rotation without accepting keys not present in the IKS.

IKS endpoints MUST be served over HTTPS [RFC9110].

### 9.2 Algorithm Agility

ZTNP is algorithm-agnostic with respect to signature schemes. Implementations MUST support at least one secure asymmetric signature scheme. Post-quantum signature schemes (e.g., ML-DSA as specified in FIPS 204) MAY be used and are RECOMMENDED for long-lived deployments.

Requesters MUST reject Posture Assertions that:

- Use an algorithm not present in the Requester's allowed list
- Reference a `kid` not found in the IKS
- Have `exp` in the past
- Have `iat` in the future beyond acceptable clock skew (RECOMMENDED: 5 minutes)
- Carry a `bind` that fails verification (Section 8.4)

---

## 10. Negotiation Messages

ZTNP messages are defined abstractly. Transport-specific encodings are defined in Section 13.

### 10.1 Discovery

**R → P: `DISCOVER`**

An optional hint object MAY be included indicating desired binding mode and minimum tier.

**P → R: `DISCOVER_RESPONSE`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ztnp_version` | string | Yes | Highest ZTNP version supported by P |
| `sub` | string | Yes | Prover subject identifier |
| `issuers` | array | Yes | Issuer identifiers whose marks P can present |
| `iks_urls` | array | No | Direct links to Issuer Key Set endpoints |
| `modes` | array | Yes | Supported binding modes: `["PA-R", "PA-C", "Mutual", "PA-O"]` |
| `features` | array | No | Optional capability strings |

### 10.2 Challenge

**R → P: `CHALLENGE`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge_nonce` | bytes | Yes | Cryptographically random, 16–32 bytes, base64url-encoded |
| `ctx` | string | No | Session context string |
| `aud` | string | No | Requester identifier |
| `mode` | string | No | Requested binding mode |
| `policy_hint` | object | No | Advisory hint (e.g., minimum tier) |

**P → R: `PROOF`**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `trust_mark` | signed token | Yes | The signed, challenge-bound Posture Assertion |
| `binding_sig` | signature | If `nonce_sig` | Detached subject signature for `nonce_sig` binding |
| `prover_meta` | object | No | Implementation info, declared constraint support |

### 10.3 Decision

R verifies the PROOF, evaluates local policy (Section 11), and MUST respond with either PERMIT or DENY.

**R → P: `PERMIT`** (if decision is `allow` or `allow_with_constraints`)

See Section 12 for Permit format.

**R → P: `DENY`** (if decision is `deny`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reasons` | array | Yes | Machine-readable reason codes + human text |
| `required_improvements` | array | No | Advisory: what P would need to be permitted |

Standard reason codes:

| Code | Meaning |
|------|---------|
| `TM_MISSING` | No Posture Assertion provided |
| `TM_EXPIRED` | Posture Assertion is past `exp` |
| `TM_INVALID_SIG` | Signature verification failed |
| `TM_BINDING_FAILED` | Challenge binding mismatch |
| `TM_ISSUER_UNKNOWN` | Issuer not in Requester's trusted set |
| `POLICY_TIER_LOW` | Prover tier below policy minimum |
| `POLICY_FLAG_BLOCKED` | A critical flag precluded the request |
| `POLICY_FRESHNESS` | Posture Assertion too old per policy |

---

## 11. Policy Model

Policies are local to the Requester. ZTNP standardizes policy inputs and outputs for interoperability while leaving policy language implementation-defined.

> **Note on tier-based constraints:** Policies that gate on `tier_min` MUST also constrain `issuers` to a trusted set whose tier semantics are known to the Requester. Tier values are issuer-profile-defined (Section 8.3) and are not comparable across issuers with different profiles. Policy authors relying solely on `tier_min` without an issuer constraint are advised that such a policy provides no meaningful assurance across arbitrary issuers.

### 11.1 Policy Inputs

- `trust_mark_payload` — the verified payload from the Posture Assertion
- `verification_result` — `valid` | `invalid` with structured reasons
- `request_context` — the action requested, data types involved, session metadata

### 11.2 Policy Output

Policy evaluation MUST yield:

| Field | Type | Description |
|-------|------|-------------|
| `decision` | enum | `allow` \| `allow_with_constraints` \| `deny` |
| `constraints` | array | Enforced constraints (if allow_with_constraints) |
| `reasons` | array | Machine-readable codes + human-readable text |

### 11.3 Standard Constraint Types

Requesters MAY issue Permits with the following standard constraints:

| Constraint | Description |
|------------|-------------|
| `data` | Allowed data classes (`public`, `internal`, `pii`, `secrets`) |
| `actions` | Allowed operations (`read`, `write`, `execute`, `email_send`, etc.) |
| `rate_limit` | Maximum actions per time window |
| `ttl` | Permit validity duration in seconds |
| `redaction` | Required redaction rules (mask tokens, truncate payloads) |
| `tools` | Specific tool names the Prover may invoke (MCP-specific) |

---

## 12. Permit Format

A Permit is a Requester-issued, short-lived authorization artifact returned after a successful `allow` or `allow_with_constraints` decision.

### 12.1 Required Fields

A Permit MUST include:

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string | Requester identifier |
| `sub` | string | Prover identifier |
| `iat` | int | Issued-at time, Unix seconds |
| `exp` | int | Expiration time, Unix seconds |
| `permit_id` | string | Unique permit identifier |
| `constraints` | object | Enforced constraints (may be empty) |
| `bound_to` | string | Optional: session or channel identifier |
| `cnf` | object | Optional: Proof-of-Possession key confirmation (see 12.2) |
| `ch_binding` | object | Optional: Channel binding descriptor (see 12.3) |

Permits MUST be signed by the Requester. Provers MUST include the Permit in subsequent requests (e.g., as a bearer token or metadata field) to enable ongoing constraint enforcement. Permits MUST NOT be reused across sessions.

### 12.2 Proof-of-Possession (PoP) Binding

A bearer Permit (one with no key confirmation) can be stolen and replayed by any party that obtains it. To prevent this, Requesters SHOULD issue PoP-bound Permits for sensitive capabilities, following the pattern established by DPoP [RFC9449].

**Issuing a PoP Permit:**

1. The Prover generates an ephemeral asymmetric key pair at session establishment.
2. The Prover includes the public key's JWK thumbprint in its PROOF metadata (`prover_meta.pop_jwk`).
3. The Requester embeds a key confirmation in the Permit:
   ```json
   { "cnf": { "jkt": "<base64url(SHA-256(public_key_JWK_thumbprint))>" } }
   ```

**Using a PoP Permit:**

For each subsequent request that carries the Permit, the Prover MUST include a DPoP-style proof: a short-lived JWS signed with the ephemeral private key that includes:

| Claim | Description |
|-------|-------------|
| `htm` | HTTP method (or MCP operation name) of the call |
| `htu` | Target URI (or MCP tool name) |
| `iat` | Issued-at, Unix seconds (MUST be within 60 seconds of Requester's clock) |
| `jti` | Unique proof nonce (prevents proof replay) |
| `permit_id` | The `permit_id` from the bound Permit |

The Requester MUST verify that `cnf.jkt` matches the key that signed the proof, that `iat` is fresh, and that `jti` has not been seen within the proof TTL.

**Conformance:** Implementations MAY support PoP binding. For agentic AI deployments handling sensitive data, PoP binding is STRONGLY RECOMMENDED. A Permit with no `cnf` field is a bearer Permit and MUST be treated as such.

### 12.3 Channel Binding

When the ZTNP exchange occurs over TLS, implementations SHOULD bind the Permit to the TLS channel using the `tls-exporter` mechanism [RFC9266]. This prevents a Permit obtained on one TLS connection from being used on a different connection (cross-connection attack).

The channel binding descriptor `ch_binding` MUST include:

| Field | Description |
|-------|-------------|
| `method` | `"tls-exporter"` |
| `label` | Exporter label (RECOMMENDED: `"EXPORTER-ZTNP-permit-binding"`) |
| `context_hash` | `base64url(SHA-256(tls_exporter_output))` |

Provers MUST verify that the TLS session's exporter output, hashed with the specified label, matches `ch_binding.context_hash` before accepting the Permit.

**Interaction with PoP:** Channel binding and PoP binding are complementary. PoP binds to a key; channel binding binds to a TLS session. For maximum security, use both. A Permit carrying both `cnf` and `ch_binding` requires an adversary to compromise the ephemeral key AND hijack the TLS channel to misuse it.

**Conformance:** Channel binding is OPTIONAL in this version of the specification. Support MUST be negotiated during Discovery via the `features` field (feature string: `"ch_binding_tls_exporter"`).

---

## 13. Transport Bindings

### 13.1 HTTP Binding (Normative)

ZTNP MAY be implemented over HTTP using the following conventions.

**Discovery:** `GET /.well-known/ztnp` returns DISCOVER_RESPONSE as JSON.

**Challenge-Response:**
```
POST /ztnp/challenge
Content-Type: application/json
{ "challenge_nonce": "<base64url>", "ctx": "http", "aud": "<R-id>" }

→ 200 OK
{ "trust_mark": "<signed-token>", "prover_meta": {} }
```

**Permit in subsequent requests:**
```
Authorization: ZTNP-Permit <permit_token>
```

**DENY response:** HTTP 403 with JSON body containing `reasons` array.

### 13.2 MCP Binding (Normative)

An MCP server implementing ZTNP as a Prover MUST expose the following tools:

```typescript
// Discovery
ztnp_discover() -> {
  ztnp_version: string,
  sub: string,
  issuers: string[],
  iks_urls?: string[],
  modes: string[],
  features?: string[]
}

// Challenge-Response (Prover side)
ztnp_prove(params: {
  challenge_nonce: string,  // base64url
  ctx?: string,
  aud?: string,
  mode?: string
}) -> {
  trust_mark: string,       // signed token
  binding_sig?: string      // present if nonce_sig method
}
```

An MCP client implementing ZTNP as a Requester SHOULD expose the following tools (OPTIONAL — these MAY be implemented locally without MCP exposure):

```typescript
// Verification
ztnp_verify(params: {
  trust_mark: string,
  challenge_nonce?: string,
  ctx?: string,
  aud?: string
}) -> {
  valid: boolean,
  payload: PostureAssertionPayload,
  reasons: Reason[]
}

// Policy evaluation
ztnp_evaluate(params: {
  policy: Policy,
  payload: PostureAssertionPayload,
  request_context: RequestContext
}) -> {
  decision: 'allow' | 'allow_with_constraints' | 'deny',
  constraints?: Constraint[],
  reasons: Reason[]
}

// Permit issuance
ztnp_issue_permit(params: {
  sub: string,
  constraints: Constraint[],
  ttl: number
}) -> {
  permit: string  // signed permit token
}
```

**MCP session establishment with ZTNP:**

1. Client calls `ztnp_discover` on server — selects binding mode
2. Client generates cryptographic `challenge_nonce`
3. Client calls `ztnp_prove({ challenge_nonce, ctx: "mcp", aud: "<client-id>" })`
4. Client verifies Posture Assertion signature using IKS; validates `bind.nonce`
5. Client evaluates local policy
6. If allowed, client calls `ztnp_issue_permit` and includes `permit` in subsequent tool call metadata:
   ```json
   { "_ztnp": { "permit": "<permit_token>" } }
   ```

In PA-C and Mutual modes, the server additionally calls `ztnp_prove` on the client, or the client includes its own Posture Assertion in the initial request.

---

## 14. Threat Model

This section describes the adversaries ZTNP is designed to defend against, the
assumptions the protocol makes about its environment, the assets being
protected, and the classes of attack the specification explicitly addresses.
Section 15 (Security Considerations) lists the specific implementation-level
mitigations that follow from this model.

### 14.1 Assumptions

ZTNP's security properties depend on the following assumptions holding. An
implementation deployed in an environment where any of these are violated
MUST compensate with out-of-band controls.

| # | Assumption |
|---|------------|
| A1 | The Issuer's signing key material is not known to any adversary. Compromise of an Issuer key invalidates all Posture Assertions signed by it. |
| A2 | The Issuer Key Set (IKS) endpoint is served over authenticated TLS and cannot be impersonated by a network adversary. |
| A3 | Implementations use a reliable time source with clock skew less than 5 minutes. Drift beyond this window may allow replay or premature acceptance of marks. |
| A4 | Requesters and Provers use cryptographically secure random number generators for nonces and key material. |
| A5 | The transport carrying ZTNP messages provides confidentiality (e.g., TLS) where the Posture Assertion or Permit contents contain sensitive posture details. |
| A6 | Requesters correctly implement policy evaluation; ZTNP defines policy inputs and outputs but not the policy engine. A flawed policy will accept marks that should be rejected. |

### 14.2 Adversaries

ZTNP defends against the following adversary classes. Each is named so that
subsequent text and issue reports can reference them precisely.

**ADV-NET (Network adversary):** Can observe, modify, replay, and drop traffic
between any two parties. Cannot break TLS. Cannot produce valid Issuer
signatures.

**ADV-RESOURCE (Malicious resource / tool server):** Controls an MCP server
or HTTP endpoint that an agent might call. Wants to induce agents to trust
it, exfiltrate data, or obtain a Permit allowing broader access than its
posture warrants. May present forged or stolen Posture Assertions.

**ADV-CALLER (Malicious agent):** Controls a ZTNP Requester. Wants to access
tools or data beyond its authorized posture. May present forged or stolen
Posture Assertions, attempt to reuse Permits, or forward Permits to colluding third
parties.

**ADV-COLLUDING (Colluding Prover + Requester):** Both endpoints are
controlled by the adversary. Wants to cause a third-party Verifier or
Relying Party to mis-classify the colluders as higher posture than they are.

**ADV-ISSUER (Compromised Issuer):** The Issuer's signing key is in adversary
hands (bounded by assumption A1; listed here to clarify what happens if A1
fails).

**ADV-PARTIAL-ISSUER (Semi-trusted Issuer):** The Issuer is legitimate but
makes assessment errors, over-attests, or defines tier semantics differently
from what the Requester assumes. Not malicious, but produces marks that a
reasonable Requester policy would reject if the full semantics were
understood.

### 14.3 Assets

ZTNP exists to protect the following assets:

| Asset | Description |
|-------|-------------|
| **Integrity of posture claims** | A Posture Assertion's claims must be attributable to the Issuer; forgery and modification must be detectable. |
| **Binding of posture to session** | A mark presented in session S must have been produced in response to the challenge for S; a mark from another session must not be accepted. |
| **Freshness of posture** | A Posture Assertion must reflect posture as of its `iat`, within a bounded freshness window. Stale posture is a security failure. |
| **Authorization scope** | A Permit's constraints must be honored; a Permit must not grant broader access than the policy decided. |
| **Confidentiality of sensitive claims** | Posture Assertions may contain posture details (e.g., which frameworks apply) that SHOULD NOT leak to unauthorized observers. |

### 14.4 Attack Surface and Mitigations

The following table maps each adversary class to the attacks it is likely to
attempt and the specification-level mitigations.

| Attack | Adversary | Mitigation | Spec Reference |
|--------|-----------|------------|----------------|
| Posture Assertion forgery | ADV-NET, ADV-RESOURCE, ADV-CALLER | Signature verification against IKS; rejection of unknown `kid` or `alg` | §9.1, §9.2 |
| Replay of a valid Posture Assertion | ADV-NET | Challenge binding (`bind.nonce`); nonce tracking; rejection of reused nonces within TTL | §8.4, §15.1 |
| Substitution: valid mark for service A presented as mark for service B | ADV-RESOURCE, ADV-CALLER | Subject binding: verify `sub` and `scope.target` match intended endpoint before acceptance | §15.4 |
| Stale mark (posture no longer valid) | ADV-RESOURCE | `exp` enforcement + independent freshness policy; short-lived marks | §9.2, §15.2, §15.6 |
| Downgrade to weaker ZTNP version | ADV-NET | Version negotiation with minimum-version policy; rejection of unexpected older versions | §15.5 |
| Algorithm downgrade / unknown algorithm | ADV-NET, ADV-RESOURCE | Requester MUST maintain an allowed algorithm list; unknown `alg` MUST be rejected | §9.2 |
| Key compromise (ADV-ISSUER) | ADV-ISSUER | Short mark lifetimes; optional revocation endpoint; key rotation schedule in IKS | §9.1, §15.3, §15.6 |
| Permit theft | ADV-NET, ADV-CALLER | Permits bound to session identifier where possible (`bound_to`); short `ttl`; MUST NOT be forwarded | §12, §15.10 |
| Confused deputy via Permit reuse | ADV-CALLER | Requester MUST enforce constraints; Permit is session-scoped, not a general capability token | §15.8 |
| Clock manipulation | ADV-NET (local), ADV-CALLER | Reliable time source assumption (A3); bounded skew tolerance; reject `iat` in far future | §15.9 |
| Tier semantic confusion (ADV-PARTIAL-ISSUER) | ADV-PARTIAL-ISSUER | Tier claims are issuer-anchored; policies MUST pair `tier_min` with an `issuers` constraint | §8.3, §11 |
| Mark disclosure to unauthorized observers | ADV-NET | Transport confidentiality (A5); minimize sensitive claims; hashed evidence references | §15.7 |
| IKS poisoning via DNS or TLS compromise | ADV-NET | TLS on IKS (A2); key caching with bounded TTL; MUST NOT accept keys absent from a freshly-fetched IKS | §9.1, §15.3 |
| Forwarded Permit laundering | ADV-CALLER + colluding third party | Permits bound to negotiating pair; MUST NOT forward; constraint enforcement | §15.10 |

### 14.5 Out of Scope

The following threats are **explicitly out of scope** for ZTNP v0.1. Deployments
that need to address them must do so through complementary mechanisms.

- **Runtime posture drift between issuance and use.** A Posture Assertion attests
  posture at time `iat`. If a vulnerability is introduced at `iat + 1`, the
  mark remains cryptographically valid until `exp` or revocation. Mitigations
  are short lifetimes and revocation endpoints, not in-protocol behavior.
- **Identity.** ZTNP does not establish who a subject is. It binds posture
  claims to a stable subject identifier. Identity must be established by a
  complementary protocol (OAuth 2.0, mTLS, SPIFFE, etc.).
- **Evidence quality.** ZTNP does not evaluate whether an Issuer's assessment
  process was competent. A Requester trusts an Issuer or does not; there is
  no in-protocol way to grade Issuers by assessment rigor. Profiles
  (Appendix D) may define evidence requirements.
- **Side-channel attacks on signature verification.** Implementations MUST
  use constant-time signature verification libraries; this is an
  implementation concern, not addressed by the specification.
- **Denial-of-service on Provers or IKS endpoints.** Standard rate limiting
  and infrastructure protections apply; ZTNP does not define them.
- **Supply chain attacks on the Issuer itself.** If an Issuer's development,
  build, or distribution pipeline is compromised, that is outside ZTNP's
  threat model. Trust in an Issuer is transitive.

---

## 15. Security Considerations

Implementations MUST consider the following. Each item is cross-referenced
from the attack surface table in Section 14.4.

1. **Replay prevention:** Enforce challenge binding; track nonces within their TTL window and reject reuse. Nonces MUST be cryptographically random and at least 128 bits.

2. **Expiration:** Reject Posture Assertions where `exp` is in the past. Enforce freshness policy independently (e.g., reject marks issued more than 24 hours ago even if not yet expired).

3. **Key rotation:** Cache IKS responses with a safe TTL (RECOMMENDED: 1 hour). Handle rotation by periodically re-fetching the IKS. MUST NOT accept keys not present in a freshly-fetched IKS.

4. **Subject binding:** Before accepting a Posture Assertion, verify that `sub` and `scope.target` match the endpoint or tool identity the Requester intended to call. Failure to do so enables substitution attacks where a valid Posture Assertion for one service is presented by another.

5. **Downgrade attacks:** During Discovery, negotiate the highest mutually supported ZTNP version. Implementations configured to require a minimum version MUST reject lower versions.

6. **Revocation:** Posture Assertions are short-lived by design (RECOMMENDED maximum lifetime: 90 days). Issuers MAY publish a revocation endpoint for emergency invalidation. Requesters SHOULD check revocation status for high-assurance use cases.

7. **Privacy:** Posture Assertions SHOULD minimize sensitive details. Use hashed evidence references rather than raw artifacts. The `sub` identifier SHOULD be a stable opaque identifier rather than a human-readable name where possible.

8. **Confused deputy:** In agentic systems a Confused Deputy attack arises when a sub-agent or tool is induced — through prompt injection, malicious instruction, or stolen context — to use its legitimate Permit to act outside the scope of the original authorized intent. ZTNP addresses this at three levels:

   - **Permit scope enforcement:** Constraints in Permits MUST be enforced by the Requester (or relayed to and enforced by the Prover). A Permit is not a capability token for arbitrary use — it is scoped to the specific negotiated session.
   - **PoP binding:** Bearer Permits are inherently vulnerable to theft and cross-session replay. For sensitive operations, Requesters SHOULD issue PoP-bound Permits (Section 12.2). A stolen PoP Permit is unusable without the corresponding ephemeral private key.
   - **Channel binding:** Cross-connection attacks — obtaining a Permit on one TLS session and using it on another — are mitigated by channel binding (Section 12.3). When supported, Requesters SHOULD bind Permits to the negotiating TLS session.
   - **Delegation chain integrity:** When a Permit flows through a chain of agents (orchestrator → sub-agent → tool), each link in the chain must be able to verify that the downstream Permit is properly derived from an upstream authorization. See Section 16.1 for the delegation chain mechanism.

9. **Time source integrity:** Implementations MUST use reliable time sources. Clock skew tolerance SHOULD NOT exceed 5 minutes. Marks with `iat` significantly in the future MUST be rejected.

10. **Permit forwarding:** Permits MUST NOT be forwarded by a Prover to a third party as a means of laundering authorization. Permits are session-scoped and bound to the negotiating pair.

11. **Prompt injection and instruction integrity:** In agentic AI deployments, Posture Assertions and Permits may be manipulated through prompt injection — an attacker controlling user-supplied content instructs an agent to call tools it would not otherwise call, with the agent's own valid Permit as the authorization vehicle. ZTNP does not prevent prompt injection at the language model layer, but Section 16 (Agentic AI Extensions) defines mechanisms to bind a Permit to a signed, verifiable statement of the original authorized intent. Implementations in agentic AI contexts are RECOMMENDED to implement Section 16.2 (Intent-Scoped Permits) for sensitive capability access.

---

---

## 16. Agentic AI Extensions

This section is **OPTIONAL**. Implementations that do not deploy ZTNP in multi-agent orchestration contexts MAY ignore it. Implementations that do deploy in such contexts SHOULD implement the applicable subsections.

The extensions in this section address security properties that arise specifically when multiple AI agents form delegation chains: one agent (the orchestrator) delegates to one or more sub-agents, which may in turn delegate further. The central security concerns are:

1. **Delegation integrity** — can a downstream recipient verify that the call chain leading to it was authorized?
2. **Intent binding** — can a resource verify that the action being requested is consistent with the original instruction that initiated the chain?
3. **Behavioral transparency** — can a Requester assert machine-readable claims about the behavioral safety properties of an AI agent beyond posture tier?

### 16.1 Delegation Chain Attestation

#### 16.1.1 Motivation

Consider an orchestrator O that delegates a task to sub-agent A, which in turn calls tool server T. T holds a policy that accepts requests only from agents authorized by a trusted orchestrator. Without a delegation chain, T cannot verify that A's call was legitimately delegated from O — it can only verify A's Posture Assertion.

A Confused Deputy attack exploits this gap: a malicious prompt injected into A's context instructs A to call T with arguments it would not otherwise use. A's Permit is valid; A's Posture Assertion is valid; only the intent is corrupted.

#### 16.1.2 Nested JWS Delegation Chain

ZTNP defines a **Delegation Chain** as a nested JWS structure in which each delegating principal adds a signature layer around the previous one. The root of the chain is a **Signed Intent** produced by the originating principal (the human user, the authenticated orchestrator, or the root trust anchor). Each downstream agent extends the chain by wrapping and signing it.

**Chain structure (three-hop example):**

```
Layer 3 (outermost): sub-agent A's JWS
  payload: {
    "del_chain_ver": "0.1",
    "delegator": "agent:A",
    "delegatee": "tool:T",
    "scope_reduction": { "actions": ["read"], "data": ["internal"] },
    "iat": <unix-seconds>,
    "exp": <unix-seconds>,
    "inner": "<Layer 2 compact JWS>"
  }

Layer 2: orchestrator O's JWS
  payload: {
    "del_chain_ver": "0.1",
    "delegator": "principal:O",
    "delegatee": "agent:A",
    "scope_reduction": { ... },
    "iat": ...,
    "exp": ...,
    "inner": "<Layer 1 compact JWS>"
  }

Layer 1 (root): Signed Intent
  payload: {
    "del_chain_ver": "0.1",
    "intent_root": true,
    "originator": "user:alice",         // or principal identifier
    "intent": "<canonical intent string>",
    "intent_hash": "<base64url(SHA-256(intent))>",
    "authorized_chain": ["principal:O", "agent:A"],
    "scope": { "actions": [...], "data": [...] },
    "iat": ...,
    "exp": ...
  }
```

**Verification rules for a chain recipient:**

1. Unwrap the outermost JWS and verify its signature against the claimed `delegator`'s public key (obtained from IKS or from the prior Posture Assertion).
2. Extract `inner` and repeat for each layer until the root (`"intent_root": true`) is reached.
3. Verify that the root is signed by a principal the recipient trusts (e.g., a known orchestrator or user identity).
4. Verify that the chain of `delegator`/`delegatee` references is unbroken: each layer's `delegatee` must equal the next layer's `delegator`.
5. Verify that no layer expands scope beyond its parent: `scope_reduction` at each layer MUST be a subset of the parent layer's scope.
6. Verify that no layer is expired (`exp` has not passed for each layer).

**Conformance:** Implementations that support delegation chains MUST enforce scope monotonicity (rule 5). A child layer MUST NOT grant broader permissions than its parent. Attempts to expand scope are a security violation and the chain MUST be rejected.

#### 16.1.3 Including the Chain in ZTNP Messages

The Delegation Chain is carried in the PROOF message as an additional field:

```json
{
  "trust_mark": "<signed-PA>",
  "delegation_chain": "<outermost-layer compact JWS>"
}
```

When a Requester's policy requires delegation chain verification (`require_delegation_chain: true`), absence of `delegation_chain` in the PROOF MUST cause a DENY with reason code `DEL_CHAIN_MISSING`.

New reason codes for delegation chain failures:

| Code | Meaning |
|------|---------|
| `DEL_CHAIN_MISSING` | Policy requires delegation chain but none was provided |
| `DEL_CHAIN_BROKEN` | Chain of delegator/delegatee references has a gap |
| `DEL_CHAIN_SCOPE_EXPANDED` | A child layer attempts to grant broader scope than its parent |
| `DEL_CHAIN_EXPIRED` | One or more chain layers has expired |
| `DEL_CHAIN_UNTRUSTED_ROOT` | The root Signed Intent is not signed by a trusted originator |

### 16.2 Intent-Scoped Permits

#### 16.2.1 Motivation

A Permit issued without reference to the original authorized intent can be presented for any action within its stated constraints, regardless of what the user actually asked the agent to do. This is the mechanism by which prompt injection escalates to a Confused Deputy attack: the injected instruction substitutes a new intent, but the Permit's constraints are broad enough to authorize it.

Intent-Scoped Permits bind the Permit to the root Signed Intent (Section 16.1.2). A resource receiving an Intent-Scoped Permit can verify not only that the caller is authorized but that the specific action being requested is consistent with the original intent.

#### 16.2.2 Intent-Scoped Permit Fields

An Intent-Scoped Permit extends the base Permit (Section 12.1) with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `intent_hash` | string | Yes | `base64url(SHA-256(canonical-intent-string))` — matches root Signed Intent's `intent_hash` |
| `intent_scope` | object | Yes | The authorized scope derived from the root Signed Intent |
| `chain_root_iss` | string | Yes | Identifier of the root Signed Intent's originator |
| `chain_root_jti` | string | Yes | `jti` of the root Signed Intent (for revocation/audit) |

The Requester MUST verify that the action requested by the Prover is within `intent_scope` before honoring the Permit. If the Prover attempts to invoke a tool or access data outside `intent_scope`, the Requester MUST deny the request even if the Permit's `constraints` would otherwise permit it.

#### 16.2.3 Scope Consistency Check

A Requester enforcing an Intent-Scoped Permit MUST evaluate the following before each gated operation:

1. Hash the current operation description (tool name + arguments + data classes) using the same canonicalization as the `intent_hash` construction.
2. Verify that the operation falls within `intent_scope`.
3. If not, return a denial with reason code `INTENT_SCOPE_MISMATCH`.

New reason code:

| Code | Meaning |
|------|---------|
| `INTENT_SCOPE_MISMATCH` | The requested operation is outside the scope authorized by the root Signed Intent |

### 16.3 Behavioral Claim Extensions

The base Posture Assertion `claims` object (Section 8.3) carries posture tier and flags. For agentic AI deployments, additional behavioral claims convey AI-specific safety properties that inform policy decisions about which capabilities an agent may access.

These claims are OPTIONAL and belong under `claims.posture.ai_behavior`.

| Claim | Type | Description |
|-------|------|-------------|
| `prompt_injection_tested` | bool | Agent has been tested against prompt injection attack scenarios |
| `tool_call_audit_logged` | bool | All tool invocations are logged to a tamper-evident audit trail |
| `tool_misuse_score` | number | Normalized score 0.0–1.0; lower = lower observed misuse risk |
| `output_validated` | bool | Agent output passes a validation step before being acted upon |
| `human_in_loop_policy` | string | One of: `never`, `on_high_risk`, `always` |
| `max_tool_call_depth` | int | Maximum depth of tool delegation chain the agent will recurse into |
| `data_exfil_controls` | bool | Agent has controls to prevent data exfiltration via tool outputs |

Profiles MAY define additional claims under `claims.posture.ai_behavior`. IANA registration is not required for profile-specific claim names.

**Interaction with policy:** The standard constraint `actions` (Section 11.3) MAY reference `ai_behavior` claims as prerequisites. For example, a policy may require `prompt_injection_tested: true` before granting `actions: ["email_send"]`.

---

---

## 17. Enrollment

This section is **OPTIONAL**. Deployments where Provers are pre-provisioned out-of-band MAY ignore it. Deployments that need a dynamic mechanism for new Provers to obtain their first Posture Assertion SHOULD implement this section or a functionally equivalent mechanism (such as the RFC 7591 compatibility profile in §17.7).

Enrollment closes the gap between "an agent exists" and "an agent has a verifiable posture." Without it, ZTNP's runtime flow implicitly assumes every Prover already holds a Posture Assertion, leaving unspecified how any Prover obtains its first one. In agentic AI deployments — where agents may be instantiated dynamically by orchestrators, CI/CD pipelines, or human users — a defined enrollment mechanism is a load-bearing requirement.

### 17.1 Enrollment Parties

| Role | Description |
|------|-------------|
| **Enrollee** | The Prover requesting to be registered and to receive its first Posture Assertion. |
| **Issuer** | The entity that accepts enrollment requests, performs (or coordinates) posture assessment, and issues the first Posture Assertion. |
| **Endorser** | An OPTIONAL principal (orchestrator, CI/CD pipeline, human user) that cryptographically vouches for the Enrollee's identity at enrollment time. Corresponds to the root of the Delegation Chain (§16.1.2). |

### 17.2 Enrollment Flow

```
Enrollee (E)              Issuer (I)              Endorser (N) [optional]
     |                        |                          |
     |--- ENROLL_INIT ------->|                          |
     |<-- ENROLL_CHALLENGE ---|                          |
     |                        |                          |
     |  [if endorsed enrollment:]                        |
     |-- request endorsement --------------------------->|
     |<----------------------- endorsement JWS ----------|
     |                        |                          |
     |--- ENROLL_REQUEST ---->|                          |
     |    (metadata,          |                          |
     |     subject_key,       |                          |
     |     endorsement?,      |                          |
     |     evidence?)         |                          |
     |                   [assess]                        |
     |<-- ENROLL_RESULT ------|                          |
     |    (sub, PA, iks_url)  |                          |
```

1. **Initiation:** Enrollee contacts the Issuer's enrollment endpoint.
2. **Challenge:** Issuer issues a nonce binding the enrollment request to this specific flow.
3. **Endorsement (optional):** Enrollee obtains a signed endorsement from an Endorser attesting to its identity. Required for Assessed Enrollment (§17.5).
4. **Request:** Enrollee submits metadata, its subject-binding public key, the endorsement (if any), and any initial posture evidence.
5. **Assessment:** Issuer verifies the challenge signature, verifies the endorsement against the Endorser's published key, and performs posture assessment.
6. **Result:** Issuer returns the assigned subject identifier, the first Posture Assertion, and the IKS URL for future verification.

### 17.3 ENROLL_REQUEST Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject_kind` | string | Yes | One of: `agent`, `service`, `tool`, `model`, `environment` |
| `subject_metadata` | object | Yes | Human-readable name, owner, intended use, capability manifest reference |
| `subject_key` | JWK | Yes | Public key the Enrollee will use for subject binding and `nonce_sig` (§8.4) |
| `challenge_nonce` | string | Yes | Nonce from the Issuer's ENROLL_CHALLENGE response |
| `challenge_sig` | signature | Yes | Enrollee's signature over `challenge_nonce` using `subject_key`, proving possession |
| `endorsement` | JWS | No | Endorser's signed attestation (required for Assessed Enrollment) |
| `evidence_refs` | array | No | SHA-256-hashed references to posture evidence (SBOM, test reports, assessment artifacts) |
| `proposed_sub` | string | No | Enrollee's preferred subject identifier; Issuer MAY reject or rewrite it |

The `endorsement` JWS, when present, MUST contain:

| Claim | Description |
|-------|-------------|
| `iss` | Endorser identifier |
| `sub` | Enrollee identifier (matches `proposed_sub` or derived from `subject_metadata.name`) |
| `iat` / `exp` | Validity window |
| `subject_key_jkt` | Thumbprint of the Enrollee's `subject_key` (binds the endorsement to the Enrollee's key) |
| `scope` | Maximum scope the Endorser authorizes this Enrollee to operate under |

### 17.4 ENROLL_RESULT Fields

| Field | Type | Description |
|-------|------|-------------|
| `sub` | string | Assigned subject identifier (namespaced by Issuer host) |
| `posture_assertion` | signed token | First Posture Assertion |
| `iks_url` | string | Canonical IKS URL for verifying future Posture Assertions from this Issuer |
| `renewal_hint_seconds` | int | RECOMMENDED interval at which the Enrollee should request a refreshed Posture Assertion |
| `endorsement_id` | string | If enrollment was endorsed, a reference to the recorded endorsement for audit |

### 17.5 Self-Enrollment vs. Assessed Enrollment

ZTNP defines two enrollment modes. Issuers MUST declare which modes they support at their well-known enrollment metadata endpoint.

**Self-Enrollment:**
- No Endorser required
- Issuer performs only proof-of-possession (signature over `challenge_nonce`)
- Issued Posture Assertion MUST have `tier <= 1` (Commitment level or equivalent) per the applicable profile
- Suitable for internal deployments where tier-1 marks are acceptable

**Assessed Enrollment:**
- Endorser signature REQUIRED
- Issuer performs posture assessment (automated, human review, or combined)
- Issued Posture Assertion MAY reflect any tier the assessment supports
- Required for cross-organization deployments and any deployment whose policies gate on `tier >= 2`

Implementations MUST NOT issue Posture Assertions above `tier 1` in response to a Self-Enrollment request. Policies that gate on `tier >= 2` therefore exclude self-enrolled subjects by construction.

### 17.6 Enrollment Anchors and Bootstrap

Assessed Enrollment requires that the Endorser's signing key is trusted by the Issuer. How the Endorser obtains its own key is deployment-specific. Recommended patterns:

- **Orchestrator-as-Endorser:** The orchestrator that spawns agents holds a long-lived signing key registered with the Issuer out-of-band (during orchestrator commissioning).
- **Human user as Endorser:** A user signs via a hardware security key (WebAuthn-style, or a platform authenticator) to endorse an agent they instantiate.
- **CI/CD pipeline as Endorser:** A pipeline holds a signing key attached to its workload identity (e.g., SPIFFE SVID, OIDC workload federation); endorsements are emitted as part of the agent build process.

The Endorser MUST appear as the root principal in any Delegation Chain (§16.1.2) created by or on behalf of the Enrollee, establishing an unbroken trust path from the original human or trusted system through to the deployed agent.

### 17.7 RFC 7591 Compatibility Profile

Deployments integrating with existing OAuth 2.0 infrastructure MAY implement ZTNP enrollment as a profile of the OAuth 2.0 Dynamic Client Registration Protocol [RFC7591]. The following field mapping applies:

| RFC 7591 Field | ZTNP Mapping |
|----------------|--------------|
| `client_name` | `subject_metadata.name` |
| `client_id` (returned) | `sub` |
| `jwks` / `jwks_uri` | `subject_key` (single JWK) or published JWKS |
| `software_id` / `software_version` | `subject_metadata.capability_manifest` |
| `contacts` | `subject_metadata.owner` |
| `scope` | Reflected in the issued Posture Assertion's `claims` and in any Endorser-imposed ceiling |

A ZTNP-aware RFC 7591 endpoint adds the following non-standard metadata fields:

- `ztnp_subject_kind` — one of the §17.3 values
- `ztnp_endorsement` — base64url-encoded Endorser JWS (if present)
- `ztnp_evidence_refs` — array of evidence reference strings

Updates and deletions of enrollment metadata follow RFC 7592 [RFC7592] (OAuth 2.0 Dynamic Client Registration Management Protocol), with the additional requirement that any change to `subject_kind` or `subject_metadata.capability_manifest` MUST trigger re-issuance (or at minimum re-evaluation) of the Posture Assertion.

### 17.8 Enrollment Transport Binding (HTTP)

When ZTNP enrollment is exposed over HTTP, the following endpoints apply:

- `GET /.well-known/ztnp-enroll` → returns `{ supported_modes, accepted_algs, rfc7591_compat_url }`
- `POST /.well-known/ztnp-enroll/init` → returns `{ challenge_nonce, challenge_exp }`
- `POST /.well-known/ztnp-enroll/submit` → accepts ENROLL_REQUEST, returns ENROLL_RESULT on success or a structured error object
- `PATCH /.well-known/ztnp-enroll/{sub}` → updates enrollment metadata (authenticated using a signature from `subject_key`)
- `DELETE /.well-known/ztnp-enroll/{sub}` → revokes enrollment (authenticated using a signature from `subject_key`)

All endpoints MUST be served over HTTPS [RFC9110]. Issuers SHOULD apply rate limiting to prevent enrollment-flood attacks (see §17.9).

### 17.9 Enrollment Security Considerations

**Endorsement forgery:** An attacker with a compromised Endorser key can endorse arbitrary Enrollees. Mitigation: Endorser keys SHOULD be managed in hardware security modules; Issuers SHOULD bind each endorsement to a challenge nonce specific to the enrollment flow so a captured endorsement cannot be replayed for a different Enrollee.

**Sybil attacks:** An attacker creates many Enrollees with trivially-satisfied metadata to obtain many Posture Assertions. Mitigation: Issuers MUST apply rate limits per Endorser (for Assessed Enrollment) and per source identity (for Self-Enrollment); Issuers MAY require additional verification (proof-of-work, human review, payment) for Self-Enrollment flows.

**Enrollment replay:** A captured ENROLL_REQUEST replayed by an attacker could register a duplicate subject or reuse a stale endorsement. Mitigation: `challenge_nonce` in ENROLL_REQUEST MUST be bound to a specific flow and expire within a short window (RECOMMENDED: 10 minutes); Issuers MUST reject requests with reused or expired nonces.

**Subject hijacking:** An attacker submits an ENROLL_REQUEST claiming a `proposed_sub` already used by a legitimate agent. Mitigation: Issuers MUST reject `proposed_sub` values that collide with existing records; subject identifiers are namespaced by Issuer host so subject uniqueness within one Issuer is sufficient.

**Revocation linkage:** An Enrollee that has been compromised or decommissioned requires its Posture Assertion to be invalidated. Enrollment records SHOULD be linked to revocation state so that deleting or revoking an enrollment (via `DELETE /.well-known/ztnp-enroll/{sub}`) automatically flags all outstanding Posture Assertions issued to that subject as revoked (mechanism deferred to §15.6).

**Cross-profile tier confusion:** A Self-Enrolled subject presented to a Requester that lacks awareness of the Issuer's tier semantics could be mistakenly treated as Assessed. Mitigation: tier claims are issuer-anchored (§8.3, §11); policies MUST pair `tier_min` with an `issuers` constraint.

New denial reason codes for enrollment failures are registered in §18.2.

---

## 18. IANA Considerations

This document requests the following IANA actions:

### 18.1 Well-Known URI Registration

Registration of `ztnp` in the "Well-Known URIs" registry [RFC8615]:

- URI Suffix: `ztnp`
- Change Controller: IETF
- Reference: This document, Section 13.1

Registration of `ztnp-enroll` in the "Well-Known URIs" registry [RFC8615]:

- URI Suffix: `ztnp-enroll`
- Change Controller: IETF
- Reference: This document, Section 17.8

### 18.2 ZTNP Registries

This document requests the creation of the following IANA registries:

**ZTNP Posture Assertion Flag Names Registry**
- Registration policy: Specification Required
- Initial values: `critical_open`, `incident_open`, `pii_access_allowed`, `secrets_access_allowed`, `code_exec_allowed`

**ZTNP Constraint Type Registry**
- Registration policy: Specification Required
- Initial values: `data`, `actions`, `rate_limit`, `ttl`, `redaction`, `tools`

**ZTNP Denial Reason Code Registry**
- Registration policy: Specification Required
- Initial values: `TM_MISSING`, `TM_EXPIRED`, `TM_INVALID_SIG`, `TM_BINDING_FAILED`, `TM_ISSUER_UNKNOWN`, `POLICY_TIER_LOW`, `POLICY_FLAG_BLOCKED`, `POLICY_FRESHNESS`, `DEL_CHAIN_MISSING`, `DEL_CHAIN_BROKEN`, `DEL_CHAIN_SCOPE_EXPANDED`, `DEL_CHAIN_EXPIRED`, `DEL_CHAIN_UNTRUSTED_ROOT`, `INTENT_SCOPE_MISMATCH`, `ENROLL_CHALLENGE_INVALID`, `ENROLL_SIG_INVALID`, `ENROLL_ENDORSEMENT_MISSING`, `ENROLL_ENDORSEMENT_INVALID`, `ENROLL_SUBJECT_COLLISION`, `ENROLL_ASSESSMENT_FAILED`, `ENROLL_TIER_EXCEEDED`

**ZTNP Binding Mode Registry**
- Registration policy: Specification Required
- Initial values: `PA-R`, `PA-C`, `Mutual`, `PA-O`

**ZTNP Enrollment Mode Registry**
- Registration policy: Specification Required
- Initial values: `self`, `assessed`

---

## 19. Conformance

An implementation is ZTNP v0.1 conformant if it:

**Prover conformance:**
- [ ] Generates Posture Assertions with all required claims (Section 8.1)
- [ ] Supports `nonce_hash` binding (Section 8.4)
- [ ] Exposes Discovery endpoint returning required fields
- [ ] Responds to CHALLENGE with a valid PROOF

**Requester conformance:**
- [ ] Verifies Posture Assertion signatures using IKS keys
- [ ] Validates `exp`, `iat`, and `bind.nonce`
- [ ] Implements Discovery + Challenge-Response flow
- [ ] Produces a deterministic `allow` / `deny` decision from policy evaluation inputs
- [ ] Rejects Posture Assertions on any of the conditions in Section 9.2

**Full implementation (both roles):**
- [ ] All of the above
- [ ] Issues Permits on successful negotiation
- [ ] Returns machine-readable DENY with reason codes

**Agentic AI Extensions conformance (OPTIONAL, Section 16):**
- [ ] Produces and validates Delegation Chain JWS structures (16.1)
- [ ] Enforces scope monotonicity across delegation layers (16.1.2)
- [ ] Issues and enforces Intent-Scoped Permits (16.2)
- [ ] Carries `claims.posture.ai_behavior` fields in Posture Assertions where applicable (16.3)

**PoP and channel binding conformance (OPTIONAL):**
- [ ] Issues PoP-bound Permits with `cnf.jkt` when requested (12.2)
- [ ] Validates per-request PoP proofs against `cnf.jkt` (12.2)
- [ ] Binds Permits to TLS session via `ch_binding` when transport is TLS (12.3)

**Enrollment conformance (OPTIONAL, Section 17):**
- [ ] Exposes ENROLL_INIT → ENROLL_CHALLENGE → ENROLL_REQUEST → ENROLL_RESULT flow (17.2)
- [ ] Verifies `challenge_sig` against `subject_key` before issuing (17.3)
- [ ] Enforces the Self-Enrollment tier ceiling (`tier <= 1`) (17.5)
- [ ] When Assessed Enrollment is supported: verifies Endorser signature and binds endorsement to challenge (17.5, 17.9)
- [ ] Links enrollment records to revocation state (17.9)
- [ ] If RFC 7591 Compatibility Profile is implemented: supports the field mapping in §17.7

---

## 20. Versioning

- `ver` in Posture Assertions uses semantic versioning: `MAJOR.MINOR.PATCH`
- Breaking changes increment MAJOR
- Backward-compatible additions increment MINOR
- Implementations MUST reject Posture Assertions with a MAJOR version they do not support

---

## 21. Normative References

| Reference | Title |
|-----------|-------|
| [RFC2119] | Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997 |
| [RFC7515] | Jones, M. et al., "JSON Web Signature (JWS)", RFC 7515, May 2015 |
| [RFC7517] | Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015 |
| [RFC9052] | Schaad, J., "CBOR Object Signing and Encryption (COSE)", RFC 9052, August 2022 |
| [RFC9110] | Fielding, R. et al., "HTTP Semantics", RFC 9110, June 2022 |
| [RFC8615] | Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)", RFC 8615, May 2019 |
| [RFC9449] | Fett, D. et al., "OAuth 2.0 Demonstrating Proof of Possession (DPoP)", RFC 9449, September 2023 |
| [RFC9266] | Whited, S., "Channel Bindings for TLS 1.3", RFC 9266, July 2022 |

---

## 22. Informative References

| Reference | Title |
|-----------|-------|
| [RFC9334] | Birkholz, H. et al., "Remote ATtestation procedureS (RATS) Architecture", RFC 9334, January 2023 |
| [RFC6749] | Hardt, D., "The OAuth 2.0 Authorization Framework", RFC 6749, October 2012 |
| [RFC7519] | Jones, M. et al., "JSON Web Token (JWT)", RFC 7519, May 2015 |
| [RFC7591] | Richer, J. et al., "OAuth 2.0 Dynamic Client Registration Protocol", RFC 7591, July 2015 |
| [RFC7592] | Richer, J. et al., "OAuth 2.0 Dynamic Client Registration Management Protocol", RFC 7592, July 2015 |
| [GNAP] | Richer, J. et al., "Grant Negotiation and Authorization Protocol (GNAP)", RFC 9635 |
| [SCITT-ARCH] | Birkholz, H. et al., "An Architecture for Trustworthy and Transparent Digital Supply Chains", Work in Progress, draft-ietf-scitt-architecture |
| [SPIFFE] | SPIFFE Project, "Secure Production Identity Framework For Everyone", https://spiffe.io |
| [MCP] | Anthropic, "Model Context Protocol Specification", https://modelcontextprotocol.io |
| [FIPS204] | NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", FIPS 204, August 2024 |
| [OWASP-LLM] | OWASP, "LLM AI Security & Governance Checklist / OWASP Top 10 for LLMs", 2025 |
| [OWASP-AGENTIC] | OWASP, "OWASP Top 10 for Agentic AI", 2026 |
| [NIST-AIRM] | NIST, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)", NIST AI 100-1, 2023 |

---

## 23. Authors' Addresses

```
Jake Miller
ZIVIS
Email: jake@zivis.ai
URI:   https://zivis.ai
```

*Note: Additional authors and contributors will be listed here upon community submission.*

---

# Appendix A — Example Policy (JSON)

```json
{
  "require": {
    "issuers": ["https://issuer.example"],
    "freshness_seconds": 86400,
    "tier_min": 3,
    "flags": {
      "critical_open": false,
      "incident_open": false
    }
  },
  "request_context_rules": {
    "action:code_exec": "deny_if_flag_false:code_exec_allowed",
    "data:pii":         "allow_if_flag_true:pii_access_allowed",
    "data:secrets":     "allow_if_flag_true:secrets_access_allowed"
  },
  "on_tm_missing": "log_and_continue"
}
```

---

# Appendix B — Example Flow (MCP, Mutual Mode)

```
1.  R calls ztnp_discover() on P
    ← { modes: ["Mutual", "PA-R"], issuers: ["https://issuer.example"], ... }

2.  R generates challenge_nonce (32 random bytes, base64url)

3.  R calls ztnp_prove({ challenge_nonce, ctx: "mcp", aud: "agent:R-id" }) on P
    ← { trust_mark: "<signed-PA>", prover_meta: {} }

4.  R fetches IKS from https://issuer.example/.well-known/ztnp-keys
    R verifies PA signature, checks exp/iat, recomputes bind.nonce hash

5.  R evaluates local policy → allow_with_constraints

6.  R calls ztnp_issue_permit({ sub: "agent:P-id", constraints: [...], ttl: 3600 })
    R sends PERMIT to P (or includes in next tool call metadata)

7.  [Mutual only] P calls ztnp_prove on R (or R includes its own PA in step 3 metadata)
    P verifies R's PA against its own policy

8.  Subsequent tool calls include:
    { "_ztnp": { "permit": "<permit_token>" } }
```

---

# Appendix C — Example Posture Assertion Payload

```json
{
  "ver": "0.1",
  "iss": "https://issuer.example",
  "sub": "agent:acme-corp/data-processor",
  "iat": 1745500800,
  "exp": 1745587200,
  "jti": "tm_01HVXYZ123ABC456DEF",
  "scope": {
    "kind": "agent",
    "target": "https://api.acme.com/agents/data-processor",
    "env": "prod",
    "components": ["data-ingestion", "data-transform"]
  },
  "claims": {
    "tier": 3,
    "posture": {
      "last_assessment": "2026-04-01T00:00:00Z",
      "assessment_type": "full",
      "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"]
    },
    "flags": {
      "critical_open": false,
      "incident_open": false,
      "pii_access_allowed": true,
      "secrets_access_allowed": false,
      "code_exec_allowed": true
    }
  },
  "bind": {
    "method": "nonce_hash",
    "nonce": "dGhpcyBpcyBhIGhhc2hlZCBub25jZQ==",
    "ctx": "mcp",
    "aud": "agent:requester-corp/orchestrator"
  }
}
```

---

# Appendix D — Profile Extension Mechanism (Informative)

ZTNP's base claims schema (§8.3) is intentionally minimal. Domain-specific semantics — AI framework compliance scores, healthcare posture claims, financial-services risk tiering, supply-chain attestation schemas — are expected to be defined in **Profiles** that extend the base.

A Profile MAY define:

- Additional structured claims under `claims.posture`
- Framework-specific tier semantics (with the issuer-anchoring constraint in §8.3)
- Standard policy packs for the domain
- Evidence-reference conventions
- Additional `flags` registered through the IANA procedure in §18.2

A Profile MUST NOT:

- Alter the required claims in §8.1
- Redefine `bind`, `scope`, or signature requirements
- Introduce transport behaviors incompatible with §13

Profile documents are published independently of this specification. Implementations conforming to this specification are not required to implement any profile. Profiles that have reached stable public status at the time of this draft's publication are out of scope for this document; see the ZTNP project index for the current list.

---

# Revision History

| Version | Date | Changes |
|---------|------|---------|
| draft-zivis-ztnp-00 | 2026-04-24 | Renamed binding mode codes to PA-R / PA-C / PA-O to parallel the Posture Assertion primitive name; rewrote Appendix D as a generic Profile Extension Mechanism (informative); stripped vendor-specific profile references from §1.3, §8.3, §14.5; replaced example issuer URLs with `https://issuer.example`; added Jake Miller to Authors' Addresses per IETF convention |
| draft-zivis-ztnp-00 | 2026-04-24 | Added §17 Enrollment defining Enrollee/Issuer/Endorser roles, ENROLL_INIT/CHALLENGE/REQUEST/RESULT flow, Self-Enrollment vs. Assessed Enrollment modes, enrollment anchors and bootstrap guidance, RFC 7591 compatibility profile, HTTP transport binding, and enrollment-specific security considerations; added seven ENROLL_* denial reason codes; added ZTNP Enrollment Mode Registry; added `ztnp-enroll` Well-Known URI; added RFC 7591 and RFC 7592 as informative references; renumbered §§18–23 |
| draft-zivis-ztnp-00 | 2026-04-21 | Renamed from draft-zivis-rats-ztnp-00; rewrote §5 as "Relationship to Existing IETF Work"; added §14 Threat Model; added §16 Agentic AI Extensions (delegation chain attestation §16.1, intent-scoped Permits §16.2, behavioral claim extensions §16.3); expanded §12 Permit Format with Proof-of-Possession binding (§12.2, DPoP-style, [RFC9449]) and TLS channel binding (§12.3, tls-exporter, [RFC9266]); strengthened §15.8 Confused Deputy with PoP, channel binding, and delegation chain guidance; added §15.11 prompt injection consideration; added RFC 9449 and RFC 9266 to normative references; added new denial reason codes DEL_CHAIN_* and INTENT_SCOPE_MISMATCH; renamed "Trust Mark" → "Posture Assertion" in prose (wire field `trust_mark` and `TM_*` reason codes retained as interface identifiers); renumbered §§17–22 |
| draft-zivis-rats-ztnp-00 | 2026-04-15 | Initial IETF Internet Draft format; added bidirectional binding modes (PA-R/C/Mutual/PA-O); added RATS relationship section; added HTTP binding; expanded nonce_sig specification; added IANA considerations; normative references; clarified tier issuer-anchoring in Sections 8.3 and 11 |
| 0.1.0 (internal) | 2026-02-20 | Initial internal draft |
