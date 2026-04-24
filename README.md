# Zero-Trust Negotiation Protocol (ZTNP)

**draft-zivis-ztnp-00** · Internet-Draft · April 2026

ZTNP is a lightweight, cryptographically verifiable protocol for agent-to-agent and agent-to-tool trust negotiation. Before two AI agents—or an agent and an MCP tool server—exchange data or invoke capabilities, ZTNP lets each side present a **Posture Assertion**: a signed token containing machine-readable security posture claims. The receiving party verifies the mark, evaluates it against local policy, and either grants a scoped **Permit** or returns a machine-readable **DENY**.

Think of it as the posture layer that identity protocols were never designed to provide. OAuth tells you *who* an agent is. ZTNP tells you *how trustworthy it is right now*.

---

## Why ZTNP Exists

Modern AI systems have an identity problem that is actually a **posture problem**.

- An MCP tool server can have a valid TLS certificate and still be running an unpatched model with no data governance controls.
- An AI agent can authenticate successfully via OAuth and still have active critical vulnerabilities or no incident-response capability.
- Multi-agent pipelines dynamically discover and invoke each other with no mechanism to ask: *"Has this service been assessed? Does it meet my minimum bar?"*

ZTNP fills this gap. It is intentionally complementary to—not a replacement for—existing identity protocols (OAuth 2.0, SPIFFE, mTLS). You still need identity. ZTNP adds posture on top.

---

## How It Works (30-Second Version)

```
Agent A (Requester)              Agent B / Tool Server (Prover)
        |                                   |
        |--- 1. DISCOVER ------------------>|
        |<-- capabilities, supported modes--|
        |                                   |
        |--- 2. CHALLENGE (nonce) --------->|
        |<-- 3. PROOF (signed Posture Assertion) --|
        |                                   |
        | [verify signature]                |
        | [check claims against policy]     |
        |                                   |
        |--- 4. PERMIT (scoped) ----------->|  ← allow_with_constraints
        |   or DENY (machine-readable) ---->|  ← deny
        |                                   |
        |--- 5. tool calls with Permit ---->|
```

1. **Discovery** — Requester asks what ZTNP modes and issuers Prover supports.
2. **Challenge** — Requester sends a random nonce to prevent replay.
3. **Proof** — Prover returns a signed Posture Assertion bound to the nonce.
4. **Decision** — Requester verifies the signature, evaluates local policy, issues a Permit or Deny.
5. **Authorized calls** — Subsequent requests carry the Permit.

The protocol adds **one round-trip** to session establishment and requires no central coordination at runtime.

---

## Enforcement: Where Does It Actually Live?

This is the question the spec intentionally leaves open—by design, because enforcement points vary by deployment. ZTNP defines **what** to check and **how** to verify it. You choose **where** to enforce it.

### Enforcement Point Options

#### 1. API Gateway / Reverse Proxy (Most Common)

Deploy ZTNP enforcement as middleware in your API gateway (Kong, nginx, Azure API Management, Envoy). The gateway:
- Intercepts inbound requests from agents
- Checks for a valid `ZTNP-Permit` bearer token
- If absent or invalid: returns HTTP 403 with machine-readable `reasons`
- If valid: passes request through with posture metadata in headers

```nginx
# Conceptual: nginx + ZTNP enforcement module
location /api/agent/ {
    ztnp_verify on;
    ztnp_require_tier 2;
    ztnp_deny_if_flag critical_open;
    proxy_pass http://backend;
}
```

This is the pattern for **protecting existing services** without modifying them.

#### 2. Agent SDK / Middleware (Built-In Enforcement)

Embed ZTNP negotiation directly in the agent runtime. Before any outbound tool call, the SDK automatically:
1. Calls `ztnp_discover` on the target
2. Negotiates a Permit
3. Attaches the Permit to subsequent calls

```typescript
// Conceptual: TypeScript agent SDK
const client = new ZTNPClient({
  policy: { tier_min: 2, flags: { critical_open: false } },
  issuerTrust: ['https://zivis.ai', 'https://internal.acme.com/ztnp']
});

// This automatically negotiates trust before the first tool call
const result = await client.call(mcpServer, 'analyze_code', { repo: '...' });
```

This is the pattern for **agent-to-agent** and **agent-to-MCP-tool** enforcement.

#### 3. MCP Server Middleware (Server-Side Gate)

An MCP server wraps its tools with ZTNP enforcement. Before serving any tool call, it verifies the calling agent's Posture Assertion. No valid Permit → the tool is never invoked.

```typescript
// Conceptual: MCP server with ZTNP gate
const server = new MCPServer({ name: 'data-processor' });
server.use(ztnpGate({
  requireCallerTier: 2,
  denyIf: { incident_open: true },
  issuers: ['https://internal.acme.com/ztnp']
}));
server.tool('process_pii', handler);
```

This is the pattern for **protecting a tool server** from untrusted callers (Caller-Presents / PA-C mode).

#### 4. Sidecar / Service Mesh (Zero Code Change)

In Kubernetes or similar environments, deploy a ZTNP sidecar container alongside every agent service. The sidecar intercepts all traffic, performs ZTNP negotiation, and proxies requests only after successful verification. The application never knows ZTNP exists.

This mirrors how SPIFFE/SPIRE or Istio mTLS works—enforcement is infrastructure-level, not application-level.

---

## Enterprise Scenarios

### Scenario 1: Active Directory / Entra ID Environment

**Context:** An enterprise has 12 AI agents deployed in Azure, all authenticated via Entra ID (OAuth 2.0 tokens). Security wants to also enforce posture requirements.

**The gap:** Entra ID tells you *who* an agent is. It doesn't tell you whether that agent has been security-assessed, has open critical vulnerabilities, or is currently under incident.

**How ZTNP fits:**

```
Agent A                    Entra ID                 Agent B
   |                          |                        |
   |--- OAuth2 auth --------->|                        |
   |<-- access token ---------|                        |
   |                                                   |
   |--- ZTNP CHALLENGE -------------------------------->|
   |<-- PROOF (Posture Assertion, signed by internal CA) ------|
   |    [verify: tier >= 2, no critical_open]           |
   |--- PERMIT ---------------------------------------->|
   |                                                   |
   |--- API call + Permit ------------------------------>|
   |   (gateway enforces both: valid Entra token        |
   |    AND valid ZTNP Permit)                          |
```

**Enforcement mechanism:**
- Azure API Management (APIM) or an Azure Front Door WAF rule checks both the Entra bearer token and the ZTNP Permit header.
- Agents that are OAuth-authenticated but lack a valid Posture Assertion receive HTTP 403.
- The Posture Assertion issuer can be the organization's own internal CA/attestation service — or ZIVIS for third-party verified marks.

**Active Directory integration specifics:**
- AD/Entra ID does not natively speak ZTNP. You don't extend the AD schema.
- The ZTNP IKS (Issuer Key Set) lives at a separate HTTPS endpoint — `https://internal.acme.com/.well-known/ztnp-keys`.
- Posture Assertions can be stored/cached in a sidecar or retrieved on-demand; they are not AD attributes.
- Conditional Access policies in Entra can be configured to require a ZTNP-compliant client assertion alongside the OAuth token (using custom claims in the token introspection flow).

**Progressive rollout (Opportunistic mode first):**

```
Phase 1: PA-O (Opportunistic) — log posture, don't block
         → Discover which agents have Posture Assertions, which don't
Phase 2: PA-R/PA-C (Enforcing) — deny agents below tier 2
         → Block unassessed agents from sensitive data paths
Phase 3: Mutual — require both sides to present marks
         → Full bidirectional posture enforcement
```

---

### Scenario 2: MCP Tool Marketplace

**Context:** An organization allows internal teams to publish MCP tool servers that other agents can call. Security wants assurance that tool servers don't have critical vulnerabilities before agents are allowed to call them.

**Enforcement (PA-R / Resource-Presents mode):**

Every MCP server in the internal marketplace must expose `ztnp_discover` and `ztnp_prove`. When an agent wants to use a tool server, it performs ZTNP negotiation first. If the tool server can't present a valid Posture Assertion from a trusted issuer with `critical_open: false`, the agent's SDK refuses to call it.

The enforcement lives in the **agent SDK** — not in the tool server. Even a malicious tool server that lies about its posture is caught because the Posture Assertion must be signed by a trusted issuer whose keys are published at a known IKS URL. A tool server can't forge a Posture Assertion.

---

### Scenario 3: Cross-Organization Agent Collaboration

**Context:** ACME Corp's orchestrator agent needs to call a data-processing agent at Partner Corp. Both orgs have their own security posture programs.

**Enforcement (Mutual mode):**

```
ACME Orchestrator              Partner Data Agent
(issued PA by ACME CA)         (issued PA by Partner CA)
        |                              |
        |--- DISCOVER ---------------->|
        |<-- modes: [Mutual] ----------|
        |                              |
        |--- CHALLENGE --------------->|
        |<-- PROOF (Partner PA) -------|
        | [ACME verifies Partner PA    |
        |  against Partner's IKS]      |
        |                              |
        |--- PROOF (ACME PA) --------->|
        |    [Partner verifies ACME PA |
        |     against ACME's IKS]      |
        |                              |
        |<-- PERMIT -------------------|
        |--- PERMIT ------------------>|
```

Each organization configures which issuers it trusts. ACME trusts ACME's CA and ZIVIS. Partner trusts Partner's CA and ZIVIS. A ZIVIS-issued Posture Assertion is mutually trusted — it's the "notary" neither party has to be.

---

### Scenario 4: Regulated Industry (Healthcare / Finance)

**Context:** A healthcare AI system wants to call a third-party medical coding agent. HIPAA requires data access controls. The organization needs to prove to auditors that only assessed agents touched PHI.

**Enforcement:**
- The data API gateway requires `pii_access_allowed: true` in the Posture Assertion before any PHI can be returned.
- Posture Assertions include an `assessment_type: "hipaa_ai"` claim in `posture` (profile-defined).
- The `permit_id` from each ZTNP session is logged to an immutable audit trail.
- Short Posture Assertion lifetimes (e.g., 24h) ensure posture is re-verified frequently.

This gives the auditor a cryptographic evidence chain: *"This agent had a valid, unexpired Posture Assertion with `pii_access_allowed: true`, issued by [assessor], when it accessed PHI record X."*

---

## What You Need to Deploy ZTNP

### Minimum Viable Deployment (Self-Issued Marks)

For internal use, an organization can issue its own Posture Assertions without any third party:

1. **Generate a signing key pair** (RS256, ES256, or ML-DSA-65)
2. **Publish an IKS endpoint** at `https://your-domain/.well-known/ztnp-keys`
3. **Issue Posture Assertions** for your agents (a simple signing script is sufficient)
4. **Deploy an enforcement point** — gateway middleware, SDK, or sidecar

Self-issued marks are appropriate for internal enforcement where the organization trusts its own attestation process. They do not provide third-party assurance to external partners.

### Third-Party Verified Marks (ZIVIS)

For marks that carry external assurance (cross-org trust, regulated environments, supply chain):

1. Submit your agent/service for assessment through a recognized Issuer (e.g., [zivis.ai](https://zivis.ai))
2. Receive an Issuer-signed Posture Assertion
3. Configure partners to trust the Issuer in their ZTNP policy

### Key Infrastructure Components

| Component | Purpose | Required? |
|-----------|---------|-----------|
| Signing key + rotation | Issue Posture Assertions | Yes |
| IKS endpoint (`/.well-known/ztnp-keys`) | Key discovery | Yes |
| ZTNP enforcement point | Gateway/SDK/sidecar | Yes |
| Policy configuration | Define tier/flag requirements | Yes |
| Nonce tracking store | Anti-replay (TTL cache) | Yes |
| Revocation endpoint | Emergency invalidation | Recommended |
| Audit log | Permit issuance record | Recommended |

---

## Enforcement Is Local; Trust Is Distributed

A key design principle: **ZTNP has no central enforcement authority.** Every Requester enforces its own policy against verified Posture Assertions. This means:

- **No single point of failure** — enforcement is at every service boundary
- **No dial-home** — verification is local (fetch IKS once, cache it, verify locally)
- **No lock-in** — any issuer can publish an IKS; any Requester can trust it

The tradeoff: you must configure which issuers you trust and what policy you apply. ZTNP gives you the mechanism; your security team defines the bar.

---

## Trust Binding Modes Summary

| Mode | Who Presents PA | Use Case |
|------|----------------|---------|
| **PA-R** (Resource-Presents) | Prover presents to Requester | Agent verifying a tool server before calling it |
| **PA-C** (Caller-Presents) | Requester presents to Prover | Sensitive tool server gating callers |
| **Mutual** | Both sides exchange PAs | Cross-org collaboration; high-value agent pipelines |
| **PA-O** (Opportunistic) | Optional; logged if missing | Progressive rollout; non-critical internal tooling |

---

## Relationship to Existing Standards

ZTNP is **complementary**, not competitive:

| Standard | What it provides | ZTNP's relationship |
|----------|-----------------|---------------------|
| OAuth 2.0 / OIDC | Identity (who you are) | ZTNP adds posture (how trustworthy you are); complementary |
| mTLS / SPIFFE | Cryptographic identity + transport security | ZTNP adds security posture claims; complementary |
| IETF RATS (RFC 9334) | Abstract architecture for remote attestation | ZTNP's role structure is RATS-shaped; not a RATS profile (RATS is hardware-centric, ZTNP is software posture) |
| IETF SCITT | Signed Statements + Transparency Service for supply-chain artifacts | A Posture Assertion MAY be encoded as a SCITT Signed Statement and optionally registered with a SCITT Transparency Service; ZTNP adds the negotiation layer SCITT does not define |
| OAuth / GNAP | Scoped authorization grants | ZTNP's Permit resembles an OAuth/GNAP grant; Permits MAY use GNAP-compatible format |
| MCP | Agent-tool capability protocol | ZTNP provides the missing trust layer for MCP |
| OWASP LLM Top 10 | AI security risk taxonomy | Posture Assertion `posture` claims can reference OWASP findings |

See draft §5 for the full relationship analysis and the open question of which IETF WG is the right venue to progress this work.

---

## Specification

The full ZTNP Internet-Draft is in this repository:

- **[draft-zivis-ztnp-00.md](./draft-zivis-ztnp-00.md)** — Full protocol specification

The draft covers:
- Posture Assertion format (Section 8)
- Challenge binding and replay prevention (Section 8.4)
- Key discovery and algorithm agility (Section 9)
- Policy model (Section 11)
- Permit format (Section 12)
- HTTP and MCP transport bindings (Section 13)
- Security considerations (Section 14)
- IANA considerations (Section 15)
- Conformance requirements (Section 16)

---

## Status

This is an early-stage Internet-Draft submitted for community feedback. We are seeking:

- **Implementation feedback** — Has anything in the spec made it hard to implement correctly?
- **Deployment feedback** — What enforcement patterns are missing or underspecified?
- **Profile contributions** — Domain-specific claim schemas (healthcare, finance, government)
- **Co-authors** — Practitioners and researchers interested in progressing this toward IETF submission

Open an issue or start a discussion in this repository. For private feedback: security@zivis.ai

---

## License

The ZTNP specification text in this repository is licensed under the IETF Trust Legal Provisions (TLP) applicable to IETF contributions.

Implementations of ZTNP are not subject to any license from ZIVIS. The protocol is open.

Profiles that extend the ZTNP base schema (Appendix D) are separately published and separately licensed. A profile is out of scope for this specification.

---

*ZIVIS · [zivis.ai](https://zivis.ai) · security@zivis.ai*