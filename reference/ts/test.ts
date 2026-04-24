/**
 * Smoke test for the reference verifier.
 *
 * Because the test vectors in ../../test-vectors/ currently contain placeholder
 * JWS tokens (pending reference-signed output), this file does not yet attempt
 * to verify them. Instead it demonstrates that the verifier compiles and
 * returns structured errors for the trivial input cases.
 *
 * A follow-up will add deterministic signing so every vector can be verified
 * end-to-end.
 */

import { verifyPostureAssertion } from "./verify.js";

async function main() {
  const iks = {
    issuer: "https://test.ztnp.example",
    keys: [
      {
        kid: "test-es256-001",
        kty: "EC",
        crv: "P-256",
        alg: "ES256",
        use: "sig",
        x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      },
    ],
  };

  const missing = await verifyPostureAssertion({
    postureAssertionJws: "",
    iks,
    now: 1745500300,
  });
  assertEq(missing.reasonCodes, ["TM_MISSING"], "empty JWS should fail with TM_MISSING");

  const malformed = await verifyPostureAssertion({
    postureAssertionJws: "not.a.jws",
    iks,
    now: 1745500300,
  });
  assertEq(malformed.reasonCodes, ["FORMAT_ERROR"], "malformed JWS should fail with FORMAT_ERROR");

  console.log("reference verifier smoke test: OK");
}

function assertEq(actual: unknown, expected: unknown, label: string) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    console.error(`FAIL: ${label}\n  expected: ${e}\n  actual:   ${a}`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
