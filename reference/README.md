# ZTNP Reference Implementation

This directory contains a minimal, illustrative reference implementation of
the ZTNP verifier. It is intended to help specification readers understand
the normative requirements and to provide implementers with a starting point.

**This is NOT production-ready code.** It lacks hardening around key
management, does minimal input validation, and uses dependencies that should
be reviewed before deployment. Do not ship it as-is.

## Contents

- `ts/` — TypeScript reference verifier (`verify.ts`) using ES256 via `jose`
- Future: `py/` — Python equivalent
- Future: additional algorithms (RS256, ML-DSA-65)

## TypeScript Reference Verifier

### What it does

The verifier implements the checks required by the draft:

1. Parse a JWS-encoded Posture Assertion
2. Resolve the `iss` to an Issuer Key Set (via a file path or URL)
3. Select the public key matching the JWS header's `kid`
4. Verify the signature
5. Check `exp` and `iat` against current time (with configurable skew)
6. Verify `bind.nonce` matches `base64url(SHA-256(challenge_nonce || ctx || aud))`
7. Verify `sub` / `scope.target` match the Requester's intended target
8. Return a structured result with `valid`, reason codes, and the parsed
   payload

### What it does NOT do

- Does not issue Posture Assertions (use a signing library directly)
- Does not implement the policy engine (call into the result from your policy
  code)
- Does not handle `nonce_sig` binding (optional per spec §8.4)
- Does not handle revocation (optional per spec §15.6)

### Install and Run

```bash
cd reference/ts
npm install
npm run test       # runs against the vectors in ../../test-vectors/
```

### Minimal Usage

```typescript
import { verifyPostureAssertion } from './verify';

const result = await verifyPostureAssertion({
  postureAssertionJws: '<signed Posture Assertion>',
  challengeNonce: '<the nonce R sent>',
  ctx: 'mcp',
  aud: 'agent:requester-test',
  intendedTarget: 'https://api.test-corp.example/agents/data-processor',
  iks: { /* Issuer Key Set contents */ },
  now: Math.floor(Date.now() / 1000),
  skewSeconds: 300,
});

if (result.valid) {
  // Feed result.payload into your policy engine
} else {
  console.log('Rejected:', result.reasonCodes);
}
```

### Conformance Note

Passing all test vectors in `../../test-vectors/` is a necessary but not
sufficient condition for conformance. The reference implementation intentionally
exercises the mandatory verifier checks. It does not exercise:

- Every algorithm listed in §9.2
- The `nonce_sig` binding path
- IKS caching and rotation
- Every transport binding

A fully conformant implementation should pass these vectors **and** its own
integration tests covering the above.

## Contributing

Ports to additional languages are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md)
for the process.
