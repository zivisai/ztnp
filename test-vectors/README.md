# ZTNP Test Vectors

This directory contains sample Posture Assertions and related artifacts for validating
ZTNP implementations. Each vector consists of:

- **Input**: the raw inputs an implementation would receive (signed Posture Assertion,
  challenge nonce, context, audience, Issuer Key Set)
- **Expected result**: whether verification should succeed or fail, and if it
  fails, which reason code applies

Use these vectors to validate that your implementation's verification logic
conforms to the spec. An implementation that accepts a vector marked
`expected: invalid` has a bug.

## File Layout

```
test-vectors/
├── README.md              (this file)
├── keys/
│   └── issuer-test.json   Test issuer key set (JWKS-like)
├── 01-valid.json          Valid Posture Assertion with nonce_hash binding
├── 02-expired.json        Valid signature, but exp is in the past
├── 03-bad-signature.json  Payload modified after signing
├── 04-bad-binding.json    bind.nonce does not match challenge
├── 05-wrong-subject.json  sub does not match intended target
├── 06-unknown-kid.json    Signed with key not in Issuer Key Set
└── 07-tier-no-issuer.json Policy would accept but requester has no issuer constraint (tier-anchoring test)
```

## Signing Details

Test vectors in this directory are signed with **ES256 (ECDSA P-256 + SHA-256)**
for simplicity. Production implementations SHOULD also test against:

- RS256 (RSA-PSS + SHA-256)
- ML-DSA-65 (FIPS 204) — post-quantum

The spec is algorithm-agnostic (§9.2). Additional vectors for other algorithms
are welcome as contributions.

## Vector Format

Each vector is a JSON document with this structure:

```json
{
  "vector_id": "01-valid",
  "description": "Well-formed Posture Assertion with nonce_hash binding",
  "inputs": {
    "trust_mark_jws": "eyJhbGciOi...",
    "challenge_nonce": "Base64URL-encoded nonce R sent",
    "ctx": "mcp",
    "aud": "agent:requester-test",
    "iks_file": "./keys/issuer-test.json",
    "current_time_unix": 1745500000
  },
  "expected": {
    "valid": true,
    "decision": "allow",
    "reason_codes": []
  }
}
```

If `expected.valid` is `false`, `expected.reason_codes` MUST contain the
specific reason code(s) a conforming implementation produces. See draft
Section 10.3 for the standard codes (`TM_EXPIRED`, `TM_INVALID_SIG`, etc.).

## Reproducing and Extending

The vectors in this directory are illustrative. Real test vector generation
(signing Posture Assertions with a deterministic ECDSA variant such as RFC 6979 is
RECOMMENDED) will be produced by the reference implementation in `reference/`
once released.

## Contributing New Vectors

If your implementation uncovers a spec edge case not covered here, please
contribute a vector. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the PR
process.

Good candidates:
- Algorithm-specific quirks (ML-DSA-65 signature format edge cases)
- Policy evaluation edge cases (tier boundary conditions)
- Interaction between `nonce_sig` binding and key rotation
- UTF-8 / canonicalization issues in `bind.nonce` hash inputs
