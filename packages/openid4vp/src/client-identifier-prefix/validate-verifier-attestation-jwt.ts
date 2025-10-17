import {
  type CallbackContext,
  decodeJwt,
  type Jwk,
  type JwtSigner,
  jwtSignerFromJwt,
  Oauth2Error,
  verifyJwt,
  zJwk,
  zJwtHeader,
} from '@openid4vc/oauth2'
import z from 'zod'

export interface VerifyAttestationOptions {
  attestedJwt: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>
  expectedAttestationJwk: Jwk
}

export async function verifyAttestation(options: VerifyAttestationOptions) {
  const { callbacks, expectedAttestationJwk, attestedJwt } = options
  if (!expectedAttestationJwk.alg) {
    throw new Oauth2Error('Invalid verifier attestation missing required alg property')
  }
  const jwtSigner: JwtSigner = {
    method: 'jwk',
    alg: expectedAttestationJwk.alg,
    publicJwk: expectedAttestationJwk,
  }

  const { header, payload } = decodeJwt({ jwt: attestedJwt })
  const verificationResult = await callbacks.verifyJwt(jwtSigner, {
    header,
    payload,
    compact: attestedJwt,
  })

  if (!verificationResult.verified) {
    throw new Oauth2Error('Invalid verifier attestation jwt. Signature verification failed.')
  }

  return verificationResult
}

export interface VerifyAttestationJwtOptions {
  attestationJwt: string
  clientId: string
  clockSkewSec?: number
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}
export async function verifyAttestationJWT(options: {
  attestationJwt: string
  clientId: string
  clockSkewSec?: number
  callbacks: Pick<CallbackContext, 'verifyJwt'>
}) {
  const errors = []

  const { header, payload } = decodeJwt({
    jwt: options.attestationJwt,
    headerSchema: z.object({ ...zJwtHeader.shape, typ: z.literal('verifier-attestation+jwt') }),
  })

  const jwtSigner = jwtSignerFromJwt({ header, payload })
  const { signer } = await verifyJwt({
    header,
    payload,
    compact: options.attestationJwt,
    signer: jwtSigner,
    verifyJwtCallback: options.callbacks.verifyJwt,
    now: new Date(),
    expectedSubject: options.clientId,
    allowedSkewInSeconds: options.clockSkewSec || 300,
    requiredClaims: ['iss', 'sub', 'exp', 'cnf'],
  })

  // 4. Verify cnf claim structure
  if (payload.cnf) {
    if (!payload.cnf.jwk) {
      errors.push('cnf claim must contain a jwk')
    } else {
      // Verify JWK has required properties for a public key
      const jwk = payload.cnf.jwk
      if (!jwk.kty) {
        errors.push('JWK missing required kty property')
      }
    }
  }

  const isValid = errors.length === 0
  if (isValid) {
    return {
      isValid: true,
      signer,
      verifierPublicKey: zJwk.parse(payload.cnf?.jwk),
    } as const
  }

  return {
    isValid: false,
    errors: errors,
    verifierPublicKey: payload.cnf?.jwk,
  } as const
}
