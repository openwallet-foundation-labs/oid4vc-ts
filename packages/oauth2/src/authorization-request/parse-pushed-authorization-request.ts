import { formatZodError, parseWithErrorHandling } from '@openid4vc/utils'
import z from 'zod'
import type { RequestLike } from '../common/z-common'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import { type ParseAuthorizationRequestResult, parseAuthorizationRequest } from './parse-authorization-request'
import { type AuthorizationRequest, zAuthorizationRequest } from './z-authorization-request'
import { isJarAuthorizationRequest, JarAuthorizationRequest, zJarAuthorizationRequest } from '../jar/z-jar-authorization-request'
import { CallbackContext } from '../callbacks'
import { parseJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import { decodeJwt } from '../common/jwt/decode-jwt'
import {
  type AuthorizationRequest,
  pushedAuthorizationRequestUriPrefix,
  zAuthorizationRequest,
} from './z-authorization-request'

export interface ParsePushedAuthorizationRequestOptions {
  request: RequestLike
  authorizationRequest: unknown,
  callbacks: Pick<CallbackContext, 'fetch'>
}
export interface ParsePushedAuthorizationRequestResult extends ParseAuthorizationRequestResult {
  authorizationRequest: AuthorizationRequest,

  /**
   * The JWT-secured request object, if the request was pushed as a JAR.
   * May be undefined if the request object is not a JAR.
   */
  authorizationRequestJwt?: string
}

/**
 * Parse an pushed authorization request.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export async function parsePushedAuthorizationRequest(
  options: ParsePushedAuthorizationRequestOptions
): Promise<ParsePushedAuthorizationRequestResult> {

  const parsed = parseWithErrorHandling(
    z.union([zAuthorizationRequest, zJarAuthorizationRequest]),
    options.authorizationRequest,
    'Invalid authorization request. Could not parse authorization request or jar.'
  )

  let parsedAuthorizationRequest;
  let authorizationRequestJwt;
  if (isJarAuthorizationRequest(parsed)) {
    const parsedJar = await parseJarRequest({ jarRequestParams: parsed, callbacks: options.callbacks })
    const jwt = decodeJwt({ jwt: parsedJar.authorizationRequestJwt })

    parsedAuthorizationRequest = zAuthorizationRequest.safeParse(jwt.payload)
    if (!parsedAuthorizationRequest.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Invalid authorization request. Could not parse jar request payload.\n${formatZodError(parsedAuthorizationRequest.error)}`,
      })
    }

    authorizationRequestJwt = parsedJar.authorizationRequestJwt;
  } else {

    parsedAuthorizationRequest = zAuthorizationRequest.safeParse(options.authorizationRequest)
    if (!parsedAuthorizationRequest.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Error occurred during validation of pushed authorization request.\n${formatZodError(parsedAuthorizationRequest.error)}`,
      })
    }
  }

  const authorizationRequest = parsedAuthorizationRequest.data
  const { clientAttestation, dpop } = parseAuthorizationRequest({
    authorizationRequest,
    request: options.request,
  })

  return {
    authorizationRequest,
    authorizationRequestJwt,
    dpop,
    clientAttestation,
  }
}

export interface ParsePushedAuthorizationRequestUriOptions {
  uri: string
}

/**
 * Parse a pushed authorization request URI prefixed with `urn:ietf:params:oauth:request_uri:`
 * and returns the identifier, without the prefix.
 *
 * @throws {Oauth2ServerErrorResponseError}
 */
export function parsePushedAuthorizationRequestUri(options: ParsePushedAuthorizationRequestUriOptions): string {
  if (!options.uri.startsWith(pushedAuthorizationRequestUriPrefix)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'request_uri' must start with the prefix "${pushedAuthorizationRequestUriPrefix}".`,
    })
  }

  return options.uri.substring(pushedAuthorizationRequestUriPrefix.length)
}
