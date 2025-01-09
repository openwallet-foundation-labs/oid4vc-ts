import { ValidationError } from '@openid4vc/utils'
import { introspectToken } from '../access-token/introspect-token'
import type { AccessTokenProfileJwtPayload } from '../access-token/v-access-token-jwt'
import type { TokenIntrospectionResponse } from '../access-token/v-token-introspection'
import { SupportedAuthenticationScheme, verifyJwtProfileAccessToken } from '../access-token/verify-access-token'
import type { CallbackContext } from '../callbacks'
import type { Jwk } from '../common/jwk/v-jwk'
import type { RequestLike } from '../common/v-common'
import { Oauth2ErrorCodes } from '../common/v-oauth2-error'
import { extractDpopJwtFromHeaders, verifyDpopJwt } from '../dpop/dpop'
import { Oauth2Error } from '../error/Oauth2Error'
import { Oauth2JwtParseError } from '../error/Oauth2JwtParseError'
import { Oauth2ResourceUnauthorizedError } from '../error/Oauth2ResourceUnauthorizedError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/v-authorization-server-metadata'

export interface VerifyResourceRequestOptions {
  /**
   * The incoming request
   */
  request: RequestLike

  /**
   * Identifier for the resource server, will be matched with the `aud` value of the access token.
   */
  resourceServer: string

  /**
   * Callbacks for verification of the access token.
   */
  callbacks: Pick<CallbackContext, 'verifyJwt' | 'hash' | 'clientAuthentication' | 'fetch'>

  /**
   * allowed auth schems for the access token. If not provided
   * all supported authentication schemes are allowed.
   */
  allowedAuthenticationSchemes?: SupportedAuthenticationScheme[]

  /**
   * List of authorization servers that this resource endpoint supports
   */
  authorizationServers: AuthorizationServerMetadata[]

  now?: Date
}

export async function verifyResourceRequest(options: VerifyResourceRequestOptions) {
  const allowedAuthenticationSchemes =
    options.allowedAuthenticationSchemes ?? Object.values(SupportedAuthenticationScheme)
  if (allowedAuthenticationSchemes.length === 0) {
    throw new Oauth2Error(
      `Emtpy array provided for 'allowedAuthenticationSchemes', provide at least one allowed authentication scheme, or remove the value to allow all supported authentication schemes`
    )
  }

  const authorizationHeader = options.request.headers.get('Authorization')
  if (!authorizationHeader) {
    throw new Oauth2ResourceUnauthorizedError(
      `No 'Authorization' header provided in request.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  const [scheme, accessToken] = authorizationHeader.split(' ', 2)
  if (!scheme || !accessToken) {
    throw new Oauth2ResourceUnauthorizedError(
      `Malformed 'Authorization' header provided in request.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  if (
    !allowedAuthenticationSchemes.includes(scheme as SupportedAuthenticationScheme) ||
    (scheme !== SupportedAuthenticationScheme.Bearer && scheme !== SupportedAuthenticationScheme.DPoP)
  ) {
    throw new Oauth2ResourceUnauthorizedError(
      `Provided authentication scheme '${scheme}' is not allowed. Allowed authentication schemes are ${allowedAuthenticationSchemes.map((s) => `'${s}'`).join(', ')}.`,
      allowedAuthenticationSchemes.map((scheme) => ({ scheme }))
    )
  }

  // We first perform the usual Bearer authentication verification
  // Try to parse and verify it as an jwt profile access token
  const verificationResult = await verifyJwtProfileAccessToken({
    accessToken,
    callbacks: options.callbacks,
    authorizationServers: options.authorizationServers,
    resourceServer: options.resourceServer,
    now: options.now,
  }).catch((error) => {
    // It's ok if we couldn't parse it as a JWT -- it means it's probably an opaque token
    if (error instanceof Oauth2JwtParseError || error instanceof ValidationError) return null

    const errorMessage = error instanceof Oauth2Error ? error.message : 'Invalid access token'
    throw new Oauth2ResourceUnauthorizedError(
      `Error occured during verification of jwt profile access token: ${error.message}`,
      {
        scheme,
        error: Oauth2ErrorCodes.InvalidToken,
        error_description: errorMessage,
      }
    )
  })

  let tokenPayload: AccessTokenProfileJwtPayload | TokenIntrospectionResponse | undefined = verificationResult?.payload
  let authorizationServer = verificationResult?.authorizationServer
  if (!tokenPayload) {
    // If there's no verification result it means it coudln't be parsed and we will try
    // to use token introspection on all authorization servers until we've found the correct one
    for (const authorizationServerMetadata of options.authorizationServers) {
      try {
        tokenPayload = await introspectToken({
          authorizationServerMetadata,
          callbacks: options.callbacks,
          token: accessToken,
          tokenTypeHint: scheme,
        })
        authorizationServer = authorizationServerMetadata

        // If we found the active token.
        if (tokenPayload.active) break
      } catch (error) {
        // No-op?
      }
    }
  }

  if (!tokenPayload || !authorizationServer) {
    throw new Oauth2ResourceUnauthorizedError('Could not verify token as jwt or using token introspection.', {
      scheme,
      error: Oauth2ErrorCodes.InvalidToken,
      error_description: 'Token is not valid',
    })
  }

  let dpopJwk: Jwk | undefined = undefined
  if (
    scheme === SupportedAuthenticationScheme.DPoP ||
    // two alternative methods to determine whether DPoP was used. As the user can
    // choose to include `Bearer` scheme even if DPoP was used
    tokenPayload.token_type === SupportedAuthenticationScheme.DPoP ||
    tokenPayload.cnf?.jkt
  ) {
    const dpopJwtResult = extractDpopJwtFromHeaders(options.request.headers)
    if (!dpopJwtResult.valid) {
      throw new Oauth2ResourceUnauthorizedError(
        `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt.`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidDpopProof,
          error_description: `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt.`,
        }
      )
    }

    if (!dpopJwtResult.dpopJwt) {
      throw new Oauth2ResourceUnauthorizedError(`Request is missing required 'DPoP' header.`, {
        scheme,
        error: Oauth2ErrorCodes.InvalidDpopProof,
        error_description: `Request is missing required 'DPoP' header.`,
      })
    }

    // Take the jwk thumbprint from the token / introspection result
    if (!tokenPayload.cnf?.jkt) {
      throw new Oauth2ResourceUnauthorizedError(
        `Token payload is missing required 'cnf.jkt' value for DPoP verification.`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidToken,
          error_description: `Token payload is missing required 'cnf.jkt' value for DPoP verification.`,
        }
      )
    }

    try {
      const decodedDpopJwt = await verifyDpopJwt({
        callbacks: options.callbacks,
        dpopJwt: dpopJwtResult.dpopJwt,
        request: options.request,
        accessToken,
        now: options.now,
        expectedJwkThumbprint: tokenPayload.cnf?.jkt,
        allowedSigningAlgs: authorizationServer.dpop_signing_alg_values_supported,
      })
      dpopJwk = decodedDpopJwt.header.jwk
    } catch (error) {
      const errorMessage = error instanceof Oauth2Error ? error.message : 'Error verifying DPoP jwt'
      throw new Oauth2ResourceUnauthorizedError(
        `Error occured during verification of jwt profile access token: ${error instanceof Error ? error.message : error}`,
        {
          scheme,
          error: Oauth2ErrorCodes.InvalidDpopProof,
          error_description: errorMessage,
        }
      )
    }
  }

  return {
    tokenPayload,
    dpopJwk,
    scheme,
    accessToken,
    authorizationServer: authorizationServer.issuer,
  }
}
