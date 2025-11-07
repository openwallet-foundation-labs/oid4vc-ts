import { ContentType, createFetcher, type Fetch } from '@openid4vc/utils'
import type { CallbackContext } from '../../callbacks'
import { decodeJwt } from '../../common/jwt/decode-jwt'
import { verifyJwt } from '../../common/jwt/verify-jwt'
import { zCompactJwe } from '../../common/jwt/z-jwe'
import { type JwtSigner, type JwtSignerWithJwk, zCompactJwt } from '../../common/jwt/z-jwt'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError'
import { type JarAuthorizationRequest, validateJarRequestParams } from '../z-jar-authorization-request'
import {
  type JarRequestObjectPayload,
  jwtAuthorizationRequestJwtHeaderTyp,
  signedAuthorizationRequestJwtHeaderTyp,
  zJarRequestObjectPayload,
} from '../z-jar-request-object'

export interface ParsedJarRequestOptions {
  jarRequestParams: JarAuthorizationRequest
  callbacks: Pick<CallbackContext, 'fetch'>
}

export interface VerifyJarRequestOptions {
  jarRequestParams: {
    client_id?: string
  }
  authorizationRequestJwt: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>
  jwtSigner: JwtSigner
}

export interface ParsedJarRequest {
  authorizationRequestJwt: string
  sendBy: 'value' | 'reference'
}

export interface VerifiedJarRequest {
  authorizationRequestPayload: JarRequestObjectPayload
  signer: JwtSignerWithJwk
  jwt: ReturnType<typeof decodeJwt<undefined, typeof zJarRequestObjectPayload>>
}
/**
 * Parse a JAR (JWT Secured Authorization Request) request by validating and optionally fetch from uri.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns An object containing the transmission method ('value' or 'reference') and the JWT request object.
 */
export async function parseJarRequest(options: ParsedJarRequestOptions): Promise<ParsedJarRequest> {
  const { callbacks } = options

  const jarRequestParams = {
    ...validateJarRequestParams(options),
    ...options.jarRequestParams,
  } as JarAuthorizationRequest & ReturnType<typeof validateJarRequestParams>

  const sendBy = jarRequestParams.request ? 'value' : 'reference'

  const authorizationRequestJwt =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      requestUri: jarRequestParams.request_uri,
      fetch: callbacks.fetch,
    }))

  return { sendBy, authorizationRequestJwt }
}

/**
 * Verifies a JAR (JWT Secured Authorization Request) request by validating and verifying signatures.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns The verified authorization request parameters and metadata
 */
export async function verifyJarRequest(options: VerifyJarRequestOptions): Promise<VerifiedJarRequest> {
  const { jarRequestParams, authorizationRequestJwt, callbacks, jwtSigner } = options

  /* Encryption is not supported */
  const requestObjectIsEncrypted = zCompactJwe.safeParse(authorizationRequestJwt).success
  if (requestObjectIsEncrypted) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Encrypted JWE request objects are not supported.',
    })
  }

  const requestIsSigned = zCompactJwt.safeParse(authorizationRequestJwt).success
  if (!requestIsSigned) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'JAR request object is not a valid JWT.',
    })
  }

  const { authorizationRequestPayload, signer, jwt } = await verifyJarRequestObject({
    authorizationRequestJwt,
    callbacks,
    jwtSigner,
  })
  if (!authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'Jar Request Object is missing the required "client_id" field.',
    })
  }

  // Expect the client_id from the jar request to match the payload
  if (jarRequestParams.client_id !== authorizationRequestPayload.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'client_id does not match the request object client_id.',
    })
  }

  return {
    jwt,
    authorizationRequestPayload,
    signer,
  }
}

async function fetchJarRequestObject(options: { requestUri: string; fetch?: Fetch }): Promise<string> {
  const { requestUri, fetch } = options

  const response = await createFetcher(fetch)(requestUri, {
    method: 'get',
    headers: {
      Accept: `${ContentType.OAuthAuthorizationRequestJwt}, ${ContentType.Jwt};q=0.9, text/plain`,
      'Content-Type': ContentType.XWwwFormUrlencoded,
    },
  }).catch(() => {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching request_object from request_uri '${requestUri}' failed`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  })

  if (!response.ok) {
    throw new Oauth2ServerErrorResponseError({
      error_description: `Fetching request_object from request_uri '${requestUri}' failed with status code '${response.status}'.`,
      error: Oauth2ErrorCodes.InvalidRequestUri,
    })
  }

  return await response.text()
}

async function verifyJarRequestObject(options: {
  authorizationRequestJwt: string
  callbacks: Pick<CallbackContext, 'verifyJwt'>
  jwtSigner: JwtSigner
}) {
  const { authorizationRequestJwt, callbacks, jwtSigner } = options

  const jwt = decodeJwt({ jwt: authorizationRequestJwt, payloadSchema: zJarRequestObjectPayload })

  const { signer } = await verifyJwt({
    verifyJwtCallback: callbacks.verifyJwt,
    compact: authorizationRequestJwt,
    header: jwt.header,
    payload: jwt.payload,

    signer: jwtSigner,
  })

  // Some existing deployments may alternatively be using both type
  if (
    jwt.header.typ !== signedAuthorizationRequestJwtHeaderTyp &&
    jwt.header.typ !== jwtAuthorizationRequestJwtHeaderTyp
  ) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: `Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt" or "jwt", received "${jwt.header.typ}".`,
    })
  }

  return {
    signer,
    jwt,
    authorizationRequestPayload: jwt.payload,
  }
}
