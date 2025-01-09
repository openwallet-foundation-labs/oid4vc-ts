import { type FetchHeaders, dateToSeconds, parseWithErrorHandling } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import { decodeJwt, jwtHeaderFromJwtSigner, jwtSignerFromJwt } from '../common/jwt/decode-jwt'
import type { JwtSigner } from '../common/jwt/v-jwt'
import { verifyJwt } from '../common/jwt/verify-jwt'
import { Oauth2Error } from '../error/Oauth2Error'
import {
  type ClientAttestationJwtHeader,
  type ClientAttestationJwtPayload,
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
  vClientAttestationJwtHeader,
  vClientAttestationJwtPayload,
} from './v-client-attestation'

export interface VerifyClientAttestationJwtOptions {
  /**
   * The compact client attestation jwt.
   */
  clientAttestationJwt: string

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date

  /**
   * Callbacks used for verifying client attestation pop jwt.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt'>

  // TODO: expectedClientId? expectedIssuer?
}

export async function verifyClientAttestationJwt(options: VerifyClientAttestationJwtOptions) {
  const { header, payload } = decodeJwt({
    jwt: options.clientAttestationJwt,
    headerSchema: vClientAttestationJwtHeader,
    payloadSchema: vClientAttestationJwtPayload,
  })

  const { signer } = await verifyJwt({
    signer: jwtSignerFromJwt({ header, payload }),
    now: options.now,
    header,
    payload,
    compact: options.clientAttestationJwt,
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'client attestation jwt verification failed',
  })

  return {
    header,
    payload,
    signer,
  }
}

export interface CreateClientAttestationJwtOptions {
  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date

  /**
   * Expiration time of the JWT.
   */
  expiresAt: Date

  /**
   * Issuer of the client attestation, usually identifier of the client backend
   */
  issuer: string

  /**
   * The client id of the client instance.
   */
  clientId: string

  /**
   * The confirmation payload for the client, attesting the `jwk`, `key_type` and `user_authentication`
   */
  confirmation: ClientAttestationJwtPayload['cnf']

  /**
   * Additional payload to include in the client attestation jwt payload. Will be applied after
   * any default claims that are included, so add claims with caution.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * Callback used for client attestation
   */
  callbacks: Pick<CallbackContext, 'signJwt'>

  /**
   * The signer of the client attestation jwt.
   */
  signer: JwtSigner
}

export async function createClientAttestationJwt(options: CreateClientAttestationJwtOptions) {
  const header = parseWithErrorHandling(vClientAttestationJwtHeader, {
    typ: 'oauth-client-attestation+jwt',
    ...jwtHeaderFromJwtSigner(options.signer),
  } satisfies ClientAttestationJwtHeader)

  const payload = parseWithErrorHandling(vClientAttestationJwtPayload, {
    iss: options.issuer,
    iat: dateToSeconds(options.issuedAt),
    exp: dateToSeconds(options.expiresAt),
    sub: options.clientId,
    cnf: options.confirmation,
    ...options.additionalPayload,
  } satisfies ClientAttestationJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, {
    header,
    payload,
  })

  return jwt
}

export function extractClientAttestationJwtsFromHeaders(headers: FetchHeaders) {
  const clientAttestationHeader = headers.get(oauthClientAttestationHeader)
  const clientAttestationPopHeader = headers.get(oauthClientAttestationPopHeader)

  if (!clientAttestationHeader || clientAttestationHeader.includes(',')) {
    throw new Oauth2Error(`Missing or invalid '${oauthClientAttestationHeader}' header.`)
  }
  if (!clientAttestationPopHeader || clientAttestationPopHeader.includes(',')) {
    throw new Oauth2Error(`Missing or invalid '${oauthClientAttestationPopHeader}' header.`)
  }

  return {
    clientAttestationPopHeader,
    clientAttestationHeader,
  }
}
