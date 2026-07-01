import { dateToSeconds, encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import { decodeJwt } from '../common/jwt/decode-jwt'
import { verifyJwt } from '../common/jwt/verify-jwt'
import type { JwtSignerJwk } from '../common/jwt/z-jwt'
import { Oauth2Error } from '../error/Oauth2Error'
import {
  type ClientAttestationJwtHeader,
  type ClientAttestationJwtPayload,
  type ClientAttestationPopJwtHeader,
  type ClientAttestationPopJwtPayload,
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
  zClientAttestationJwtHeader,
  zClientAttestationJwtPayload,
  zClientAttestationPopJwtHeader,
  zClientAttestationPopJwtPayload,
} from './z-client-attestation'

export interface RequestClientAttestationOptions {
  /**
   * The challenge provided by the authorization server to include in the client attestation pop jwt.
   */
  challenge?: string

  /**
   * @deprecated Renamed to `challenge` in draft 06. If `challenge` is not set, this value is used.
   */
  nonce?: string

  /**
   * The client attestation jwt to create the pop for.
   */
  jwt: string

  /**
   * The signer of the client attestation pop jwt.
   *
   * Will be extracted from the client attestation if not provided.
   */
  signer?: JwtSignerJwk
}

export async function createClientAttestationForRequest(
  options: { clientAttestation: RequestClientAttestationOptions } & Pick<
    CreateClientAttestationPopJwtOptions,
    'callbacks' | 'authorizationServer'
  >
) {
  const clientAttestationPopJwt = await createClientAttestationPopJwt({
    authorizationServer: options.authorizationServer,
    clientAttestation: options.clientAttestation.jwt,
    callbacks: options.callbacks,
    signer: options.clientAttestation.signer,
    // TODO: support dynamic fetching of the challenge from the `challenge_endpoint`
    challenge: options.clientAttestation.challenge ?? options.clientAttestation.nonce,
  })

  return {
    headers: {
      [oauthClientAttestationHeader]: options.clientAttestation.jwt,
      [oauthClientAttestationPopHeader]: clientAttestationPopJwt,
    },
  }
}

export interface VerifyClientAttestationPopJwtOptions {
  /**
   * The compact client attestation pop jwt.
   */
  clientAttestationPopJwt: string

  /**
   * The issuer identifier of the authorization server handling the client attestation.
   */
  authorizationServer: string

  /**
   * The expected value of the `aud` claim. Defaults to `authorizationServer`.
   *
   * draft 09 allows the audience to be a Resource Server identifier URL in addition to the
   * authorization server issuer URL; set this when verifying a PoP JWT at a resource server.
   */
  expectedAudience?: string

  /**
   * Expected challenge in the payload. If not provided the challenge won't be validated.
   *
   * Matched against the `challenge` claim (draft 06+) and, for backwards compatibility,
   * the legacy `nonce` claim.
   */
  expectedChallenge?: string

  /**
   * @deprecated Renamed to `expectedChallenge` in draft 06. If `expectedChallenge` is not set,
   * this value is used.
   */
  expectedNonce?: string

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

  /**
   * Allowed skew time in seconds for validity of token. Used for `exp` and `nbf`
   * verification.
   *
   * @default 0
   */
  allowedSkewInSeconds?: number

  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>

  /**
   * The parsed and verified client attestation jwt
   */
  clientAttestation: {
    header: ClientAttestationJwtHeader
    payload: ClientAttestationJwtPayload
  }
}

export type VerifiedClientAttestationPopJwt = Awaited<ReturnType<typeof verifyClientAttestationPopJwt>>
export async function verifyClientAttestationPopJwt(options: VerifyClientAttestationPopJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationPopJwt,
    headerSchema: zClientAttestationPopJwtHeader,
    payloadSchema: zClientAttestationPopJwtPayload,
  })

  // `iss` was removed from the Client Attestation PoP JWT in draft 08. Only validate it against
  // the client attestation `sub` when a legacy (<= draft 07) PoP JWT still includes it.
  if (payload.iss !== undefined && payload.iss !== options.clientAttestation.payload.sub) {
    throw new Oauth2Error(
      `Client Attestation Pop jwt contains 'iss' (client_id) value '${payload.iss}', but expected 'sub' value from client attestation '${options.clientAttestation.payload.sub}'`
    )
  }

  // `challenge` (draft 06+) replaced `nonce`. Accept either claim for backwards compatibility.
  const expectedChallenge = options.expectedChallenge ?? options.expectedNonce
  if (expectedChallenge !== undefined && expectedChallenge !== (payload.challenge ?? payload.nonce)) {
    throw new Oauth2Error("Client Attestation Pop jwt 'challenge' does not match expected value.")
  }

  const { signer } = await verifyJwt({
    signer: {
      alg: header.alg,
      method: 'jwk',
      publicJwk: options.clientAttestation.payload.cnf.jwk,
    },
    now: options.now,
    header,
    payload,
    expectedAudience: options.expectedAudience ?? options.authorizationServer,
    compact: options.clientAttestationPopJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'client attestation pop jwt verification failed',
    allowedSkewInSeconds: options.allowedSkewInSeconds,
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface CreateClientAttestationPopJwtOptions {
  /**
   * The challenge provided by the authorization server to include in the client attestation pop jwt.
   */
  challenge?: string

  /**
   * @deprecated Renamed to `challenge` in draft 06. If `challenge` is not set, this value is used.
   */
  nonce?: string

  /**
   * The audience authorization server identifier
   */
  authorizationServer: string

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * The client attestation to create the Pop for
   */
  clientAttestation: string

  /**
   * Additional payload to include in the client attestation pop jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * Callback used for dpop
   */
  callbacks: Pick<CallbackContext, 'generateRandom' | 'signJwt'>

  /**
   * The signer of jwt. Only jwk signer allowed.
   *
   * If not provided, the signer will be derived based on the
   * `cnf.jwk` and `alg` in the client attestation.
   */
  signer?: JwtSignerJwk
}

export async function createClientAttestationPopJwt(options: CreateClientAttestationPopJwtOptions) {
  const clientAttestation = decodeJwt({
    jwt: options.clientAttestation,
    headerSchema: zClientAttestationJwtHeader,
    payloadSchema: zClientAttestationJwtPayload,
  })

  const signer = options.signer ?? {
    method: 'jwk',
    alg: clientAttestation.header.alg,
    publicJwk: clientAttestation.payload.cnf.jwk,
  }

  const header = parseWithErrorHandling(zClientAttestationPopJwtHeader, {
    typ: 'oauth-client-attestation-pop+jwt',
    alg: signer.alg,
  } satisfies ClientAttestationPopJwtHeader)

  // `iss` (removed in draft 08) and `exp` (removed in draft 06) are no longer part of the
  // Client Attestation PoP JWT. `challenge` (draft 06+) replaces the legacy `nonce`.
  const payload = parseWithErrorHandling(zClientAttestationPopJwtPayload, {
    aud: options.authorizationServer,
    iat: dateToSeconds(options.issuedAt ?? new Date()),
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
    challenge: options.challenge ?? options.nonce,
    ...options.additionalPayload,
  } satisfies ClientAttestationPopJwtPayload)

  const { jwt } = await options.callbacks.signJwt(signer, {
    header,
    payload,
  })

  return jwt
}
