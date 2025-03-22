import type { CallbackContext } from '../callbacks'
import { extractJwkFromJwksForJwt } from '../common/jwk/jwks'
import { decodeJwt } from '../common/jwt/decode-jwt'
import { verifyJwt } from '../common/jwt/verify-jwt'
import { Oauth2Error } from '../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import { fetchJwks } from '../metadata/fetch-jwks-uri'
import { zAccessTokenProfileJwtHeader, zAccessTokenProfileJwtPayload } from './z-access-token-jwt'

export enum SupportedAuthenticationScheme {
  Bearer = 'Bearer',
  DPoP = 'DPoP',
}

export interface VerifyJwtProfileAccessTokenOptions {
  /**
   * The access token
   */
  accessToken: string

  /**
   * Callbacks used for verifying the access token
   */
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'fetch'>

  /**
   * If not provided current time will be used
   */
  now?: Date

  /**
   * Identifier of the resource server
   */
  resourceServer: string

  /**
   * List of authorization servers that this resource endpoint supports
   */
  authorizationServers: AuthorizationServerMetadata[]
}

/**
 * Verify an access token as a JWT Profile access token.
 *
 * @throws {@link ValidationError} if the JWT header or payload does not align with JWT Profile rules
 * @throws {@link Oauth2JwtParseError} if the jwt is not a valid jwt format, or the jwt header/payload cannot be parsed as JSON
 * @throws {@link Oauth2JwtVerificationError} if the JWT verification fails (signature or nbf/exp)
 * @throws {@link Oauth2JwtVerificationError} if the JWT verification fails (signature or nbf/exp)
 */
export async function verifyJwtProfileAccessToken(options: VerifyJwtProfileAccessTokenOptions) {
  const decodedJwt = decodeJwt({
    jwt: options.accessToken,
    headerSchema: zAccessTokenProfileJwtHeader,
    payloadSchema: zAccessTokenProfileJwtPayload,
  })

  const authorizationServer = options.authorizationServers.find(({ issuer }) => decodedJwt.payload.iss === issuer)
  if (!authorizationServer) {
    // Authorization server not found
    throw new Oauth2Error(
      `Access token jwt contains unrecognized authorization server 'iss' value of '${decodedJwt.payload.iss}'`
    )
  }

  const jwksUrl = authorizationServer.jwks_uri
  if (!jwksUrl) {
    throw new Oauth2Error(
      `Authorization server '${authorizationServer.issuer}' does not have a 'jwks_uri' parameter to fetch JWKs.`
    )
  }

  const jwks = await fetchJwks(jwksUrl, options.callbacks.fetch)
  const publicJwk = extractJwkFromJwksForJwt({
    kid: decodedJwt.header.kid,
    jwks,
    use: 'sig',
  })

  await verifyJwt({
    compact: options.accessToken,
    header: decodedJwt.header,
    payload: decodedJwt.payload,
    signer: { method: 'jwk', publicJwk, alg: decodedJwt.header.alg },
    verifyJwtCallback: options.callbacks.verifyJwt,
    errorMessage: 'Error during verification of access token jwt.',
    now: options.now,
    expectedAudience: options.resourceServer,
  })

  return {
    header: decodedJwt.header,
    payload: decodedJwt.payload,
    authorizationServer,
  }
}
