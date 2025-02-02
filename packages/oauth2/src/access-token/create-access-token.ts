import { addSecondsToDate, dateToSeconds, encodeToBase64Url, parseWithErrorHandling } from '@openid4vc/utils'
import type { CallbackContext } from '../callbacks'
import { HashAlgorithm } from '../callbacks'
import { calculateJwkThumbprint } from '../common/jwk/jwk-thumbprint'
import type { Jwk } from '../common/jwk/z-jwk'
import { jwtHeaderFromJwtSigner } from '../common/jwt/decode-jwt'
import type { JwtSigner } from '../common/jwt/z-jwt'
import {
  type AccessTokenProfileJwtHeader,
  type AccessTokenProfileJwtPayload,
  zAccessTokenProfileJwtHeader,
  zAccessTokenProfileJwtPayload,
} from './z-access-token-jwt'

export interface CreateAccessTokenOptions {
  callbacks: Pick<CallbackContext, 'signJwt' | 'generateRandom' | 'hash'>

  /**
   * public dpop jwk key. Will be encoded as jwk thubmprint in the `cnf.jkt` claim.
   */
  dpopJwk?: Jwk

  /**
   * scope of the access token. If the authorization request included scopes
   * they should be added to the access token as well
   */
  scope?: string

  /**
   * Client id to which the access token is bound.
   * Can be undefined in case of anonymous access using pre authorized code flow
   */
  clientId?: string

  /**
   * The authorization server that issues the access token
   */
  authorizationServer: string

  /**
   * Signer of the access token
   */
  signer: JwtSigner

  /**
   * Number of seconds after which the token will expire
   */
  expiresInSeconds: number

  /**
   * The audience of the access token. Should be the `resource` if included in the authorization request
   */
  audience: string

  /**
   * The subject of the access token. When a resource owner is involved,
   * it should be an identifier for the resource owner.
   */
  subject: string

  /**
   * Date that should be used as now. If not provided current date will be used.
   */
  now?: Date

  /**
   * Additional payload claims to include in the access token JWT.
   * Will override existing claims so you can override default behaviour, but be careful.
   */
  additionalPayload?: Record<string, unknown>
}

/**
 * Create an oauth2 access token conformant with "JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens"
 * @see https://datatracker.ietf.org/doc/html/rfc9068
 */
export async function createAccessTokenJwt(options: CreateAccessTokenOptions) {
  const header = parseWithErrorHandling(zAccessTokenProfileJwtHeader, {
    ...jwtHeaderFromJwtSigner(options.signer),
    typ: 'at+jwt',
  } satisfies AccessTokenProfileJwtHeader)

  const now = options.now ?? new Date()

  const payload = parseWithErrorHandling(zAccessTokenProfileJwtPayload, {
    iat: dateToSeconds(now),
    exp: dateToSeconds(addSecondsToDate(now, options.expiresInSeconds)),
    aud: options.audience,
    iss: options.authorizationServer,
    jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
    client_id: options.clientId,
    sub: options.subject,
    scope: options.scope,
    cnf: options.dpopJwk
      ? {
          jkt: await calculateJwkThumbprint({
            hashAlgorithm: HashAlgorithm.Sha256,
            hashCallback: options.callbacks.hash,
            jwk: options.dpopJwk,
          }),
        }
      : undefined,
    ...options.additionalPayload,
  } satisfies AccessTokenProfileJwtPayload)

  const { jwt } = await options.callbacks.signJwt(options.signer, {
    header,
    payload,
  })

  return {
    jwt,
  }
}
