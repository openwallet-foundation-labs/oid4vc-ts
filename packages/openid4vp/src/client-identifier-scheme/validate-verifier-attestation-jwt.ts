import {
  type CallbackContext,
  type Jwk,
  type JwtHeader,
  type JwtPayload,
  type JwtSigner,
  Oauth2Error,
  decodeJwt,
} from '@openid4vc/oauth2'

/**
 * Verifies a Verifier Attestation according to the OpenID4VP specification
 * @param {Object} header - The decoded JWT header
 * @param {Object} payload - The decoded JWT payload
 * @param {Object} options - Additional verification options
 * @param {number} [options.clockSkewSec=300] - Allowed clock skew in seconds
 * @returns {Object} Result object with success boolean and any error message
 */
export async function verifyAttestation(
  attestedJws: string,
  options: { callbacks: Pick<CallbackContext, 'verifyJwt'>; attestationJwtCnfJwk: Jwk }
) {
  const { callbacks, attestationJwtCnfJwk } = options
  if (!attestationJwtCnfJwk.alg) {
    throw new Oauth2Error('Invalid verifier attestation missing required alg property')
  }
  const jwtSigner: JwtSigner = {
    method: 'jwk',
    alg: attestationJwtCnfJwk.alg,
    publicJwk: attestationJwtCnfJwk,
  }

  const { header, payload } = decodeJwt({ jwt: attestedJws })
  const verificationResult = await callbacks.verifyJwt(jwtSigner, {
    header,
    payload,
    compact: attestedJws,
  })

  if (!verificationResult.verified) {
    throw new Oauth2Error('Invalid verifier attestation jwt. Signature verification failed.')
  }

  return verificationResult
}

// Example usage:
/*
const result = verifyAttestationJWT({
  typ: 'verifier-attestation+jwt',
  alg: 'ES256'
}, {
  iss: 'https://issuer.example.com',
  sub: 'client123',
  exp: Math.floor(Date.now() / 1000) + 3600,
  cnf: {
    jwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
      y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM'
    }
  }
});
*/

/**
 * Verifies a Verifier Attestation JWT according to the OpenID4VP specification
 * @param {Object} header - The decoded JWT header
 * @param {Object} payload - The decoded JWT payload
 * @param {Object} options - Additional verification options
 * @param {number} [options.clockSkewSec=300] - Allowed clock skew in seconds
 * @returns {Object} Result object with success boolean and any error message
 */
export async function verifyAttestationJWT(
  jwt: {
    signer: JwtSigner
    header: JwtHeader
    payload: JwtPayload
    compact: string
  },
  options: { clientId: string; clockSkewSec?: number; callbacks: Pick<CallbackContext, 'verifyJwt'> }
) {
  const { header, payload, compact } = jwt
  const errors = []
  const clockSkewSec = options.clockSkewSec || 300 // 5 minute default clock skew
  const now = Math.floor(Date.now() / 1000)

  // IT is not defined in openid4vp how to resolve the public key for verifying the attestation jwt
  // it is just mentioned that the key may be resolved from the issuer
  const verificationResult = await options.callbacks.verifyJwt(jwt.signer, {
    header,
    payload,
    compact,
  })

  if (!verificationResult.verified) {
    errors.push('Invalid verifier attestation jwt. Signature verification failed.')
  }

  // 1. Verify header has correct type
  if (header.typ !== 'verifier-attestation+jwt') {
    errors.push('Invalid typ header. Must be "verifier-attestation+jwt"')
  }

  // 2. Verify required claims are present
  const requiredClaims = ['iss', 'sub', 'exp', 'cnf']
  for (const claim of requiredClaims) {
    if (!payload[claim]) {
      errors.push(`Missing required claim: ${claim}`)
    }
  }

  // 3. Verify time-based claims
  if (payload.exp && payload.exp <= now - clockSkewSec) {
    errors.push('Token has expired')
  }

  if (payload.nbf && payload.nbf > now + clockSkewSec) {
    errors.push('Token cannot be used yet (nbf)')
  }

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

  // 5. Verify client_id format
  if (payload.sub) {
    if (typeof payload.sub !== 'string' || options.clientId !== payload.sub) {
      errors.push(`sub claim must match the clientId '${options.clientId}'`)
    }
  }

  const isValid = errors.length === 0
  if (isValid) {
    return {
      isValid: true,
      jwtHeader: header,
      jwtPayload: payload,
      // biome-ignore lint/style/noNonNullAssertion: <explanation>
      verifierPublicKey: payload.cnf?.jwk!,
    } as const
  }

  return {
    isValid: false,
    errors: errors,
    jwtHeader: header,
    jwtPayload: payload,
    verifierPublicKey: payload.cnf?.jwk,
  } as const
}
