import { addSecondsToDate, dateToSeconds, encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
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
   * Dpop nonce to use for constructing the client attestation pop jwt
   */
  nonce?: string

  /**
   * Expiration time of the client attestation pop jwt.
   *
   * @default 5 minutes after issuance date
   */
  expiresAt?: Date

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
    expiresAt: options.clientAttestation.expiresAt,
    signer: options.clientAttestation.signer,
    // TODO: support dynamic fetching of the nonce
    nonce: options.clientAttestation.nonce,
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
   * The issuer identifier of the authorization server handling the client attestation
   */
  authorizationServer: string

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

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

export async function verifyClientAttestationPopJwt(options: VerifyClientAttestationPopJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationPopJwt,
    headerSchema: zClientAttestationPopJwtHeader,
    payloadSchema: zClientAttestationPopJwtPayload,
  })

  if (payload.iss !== options.clientAttestation.payload.sub) {
    throw new Oauth2Error(
      `Client Attestation Pop jwt contains 'iss' (client_id) value '${payload.iss}', but expected 'sub' value from client attestation '${options.clientAttestation.payload.sub}'`
    )
  }

  if (payload.aud !== options.authorizationServer) {
    throw new Oauth2Error(
      `Client Attestation Pop jwt contains 'aud' value '${payload.aud}', but expected authorization server identifier '${options.authorizationServer}'`
    )
  }

  const { signer } = await verifyJwt({
    signer: {
      alg: header.alg,
      method: 'jwk',
      publicJwk: options.clientAttestation.payload.cnf.jwk,
    },
    now: options.now,
    header,
    expectedNonce: options.expectedNonce,
    payload,
    compact: options.clientAttestationPopJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'client attestation pop jwt verification failed',
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface CreateClientAttestationPopJwtOptions {
  /**
   * Client attestation Pop nonce value
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
   * Expiration time of the JWT. If not proided 1 minute will be added to the `issuedAt`
   */
  expiresAt?: Date

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

  const expiresAt = options.expiresAt ?? addSecondsToDate(options.issuedAt ?? new Date(), 1 * 60)

  const payload = parseWithErrorHandling(zClientAttestationPopJwtPayload, {
    aud: options.authorizationServer,
    iss: clientAttestation.payload.sub,
    iat: dateToSeconds(options.issuedAt),
    exp: dateToSeconds(expiresAt),
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
    nonce: options.nonce,
    ...options.additionalPayload,
  } satisfies ClientAttestationPopJwtPayload)

  const { jwt } = await options.callbacks.signJwt(signer, {
    header,
    payload,
  })

  return jwt
}
