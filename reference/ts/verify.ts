/**
 * ZTNP Reference Verifier (TypeScript)
 *
 * Illustrative implementation of the verifier checks defined in
 * draft-zivis-ztnp-00. NOT production-ready.
 *
 * License: Apache-2.0
 */

import {
  jwtVerify,
  importJWK,
  decodeProtectedHeader,
  type JWK,
} from "jose";
import { createHash } from "node:crypto";

export type ReasonCode =
  | "TM_MISSING"
  | "TM_EXPIRED"
  | "TM_NOT_YET_VALID"
  | "TM_INVALID_SIG"
  | "TM_BINDING_FAILED"
  | "TM_ISSUER_UNKNOWN"
  | "SUBJECT_MISMATCH"
  | "POLICY_INCOMPLETE_TIER_NO_ISSUER"
  | "FORMAT_ERROR";

export interface IssuerKeySet {
  issuer: string;
  keys: Array<
    JWK & { kid: string; alg?: string; valid_from?: number; valid_until?: number }
  >;
}

export interface PostureAssertionPayload {
  ver: string;
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  scope: { kind: string; target: string; env?: string; components?: string[] };
  claims: {
    tier: number;
    posture?: Record<string, unknown>;
    flags?: Record<string, boolean>;
  };
  bind?: { method: "nonce_hash" | "nonce_sig"; nonce: string; ctx?: string; aud?: string };
}

export interface VerifyInputs {
  postureAssertionJws: string;
  challengeNonce?: string;
  ctx?: string;
  aud?: string;
  intendedTarget?: string;
  iks: IssuerKeySet;
  now: number;
  skewSeconds?: number;
  maxFreshnessSeconds?: number;
}

export interface VerifyResult {
  valid: boolean;
  payload?: PostureAssertionPayload;
  reasonCodes: ReasonCode[];
  humanMessages: string[];
}

function fail(codes: ReasonCode[], messages: string[], payload?: PostureAssertionPayload): VerifyResult {
  return { valid: false, reasonCodes: codes, humanMessages: messages, payload };
}

function base64UrlSha256(input: string): string {
  const digest = createHash("sha256").update(input, "utf8").digest();
  return digest.toString("base64url");
}

export async function verifyPostureAssertion(inputs: VerifyInputs): Promise<VerifyResult> {
  const { postureAssertionJws, iks, now, skewSeconds = 300 } = inputs;
  const reasonCodes: ReasonCode[] = [];
  const messages: string[] = [];

  if (!postureAssertionJws) {
    return fail(["TM_MISSING"], ["No Posture Assertion provided"]);
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(postureAssertionJws);
  } catch {
    return fail(["FORMAT_ERROR"], ["Posture Assertion is not a valid JWS"]);
  }

  const kid = header.kid;
  if (!kid) {
    return fail(["TM_INVALID_SIG"], ["JWS header missing kid"]);
  }

  const jwk = iks.keys.find((k) => k.kid === kid);
  if (!jwk) {
    return fail(["TM_INVALID_SIG"], [`No key with kid '${kid}' in IKS for issuer ${iks.issuer}`]);
  }

  let key;
  try {
    key = await importJWK(jwk, header.alg);
  } catch (e) {
    return fail(["FORMAT_ERROR"], [`Unable to import JWK: ${(e as Error).message}`]);
  }

  let payload: PostureAssertionPayload;
  try {
    const verified = await jwtVerify(postureAssertionJws, key, {
      clockTolerance: skewSeconds,
      currentDate: new Date(now * 1000),
    });
    payload = verified.payload as unknown as PostureAssertionPayload;
  } catch (e) {
    const msg = (e as Error).message;
    if (/exp/i.test(msg)) return fail(["TM_EXPIRED"], [msg]);
    if (/iat|nbf/i.test(msg)) return fail(["TM_NOT_YET_VALID"], [msg]);
    return fail(["TM_INVALID_SIG"], [msg]);
  }

  if (payload.iss !== iks.issuer) {
    reasonCodes.push("TM_ISSUER_UNKNOWN");
    messages.push(`iss claim '${payload.iss}' does not match provided IKS issuer '${iks.issuer}'`);
  }

  const { maxFreshnessSeconds } = inputs;
  if (maxFreshnessSeconds !== undefined && now - payload.iat > maxFreshnessSeconds) {
    reasonCodes.push("TM_EXPIRED");
    messages.push(
      `Posture Assertion age ${now - payload.iat}s exceeds freshness policy ${maxFreshnessSeconds}s`,
    );
  }

  if (payload.bind) {
    if (payload.bind.method === "nonce_hash") {
      if (!inputs.challengeNonce) {
        reasonCodes.push("TM_BINDING_FAILED");
        messages.push("Posture Assertion has nonce_hash binding but no challenge_nonce provided");
      } else {
        const ctx = payload.bind.ctx ?? inputs.ctx ?? "";
        const aud = payload.bind.aud ?? inputs.aud ?? "";
        const expected = base64UrlSha256(inputs.challengeNonce + ctx + aud);
        if (expected !== payload.bind.nonce) {
          reasonCodes.push("TM_BINDING_FAILED");
          messages.push(
            `bind.nonce mismatch (expected=${expected} got=${payload.bind.nonce})`,
          );
        }
      }
    } else if (payload.bind.method === "nonce_sig") {
      reasonCodes.push("FORMAT_ERROR");
      messages.push("nonce_sig binding is optional and not implemented by this reference verifier");
    }
  }

  if (inputs.intendedTarget) {
    const target = payload.scope?.target;
    if (target !== inputs.intendedTarget) {
      reasonCodes.push("SUBJECT_MISMATCH");
      messages.push(
        `scope.target '${target}' does not match intended target '${inputs.intendedTarget}'`,
      );
    }
  }

  if (reasonCodes.length > 0) {
    return fail(reasonCodes, messages, payload);
  }
  return { valid: true, payload, reasonCodes: [], humanMessages: [] };
}
