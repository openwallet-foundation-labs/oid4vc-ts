import { type CallbackContext, type JwtSigner, Oauth2Error } from '@openid4vc/oauth2'
import { URL, URLSearchParams, objectToQueryParams, parseWithErrorHandling } from '@openid4vc/utils'
import { createJarAuthRequest } from '../jar/create-jar-auth-request'
import {
  type WalletVerificationOptions,
  validateOpenid4vpAuthorizationRequestPayload,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'

export interface CreateOpenid4vpAuthorizationRequestOptions {
  scheme?: string
  requestParams: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar?: {
    requestUri: string
    jwtSigner: JwtSigner
    additionalJwtPayload?: Record<string, unknown>
  }
  wallet?: WalletVerificationOptions
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

/**
 * Creates an OpenID4VP authorization request, optionally with a JWT Secured Authorization Request (JAR)
 * If the request is created after receiving wallet metadata via a POST to the request_uri endpoint, the wallet nonce needs to be provided
 *
 * @param options Configuration options for creating the authorization request
 * @param input.scheme Optional URI scheme to use (defaults to 'openid4vp://')
 * @param input.requestParams The OpenID4VP authorization request parameters
 * @param input.jar Optional JWT Secured Authorization Request (JAR) configuration
 * @param input.jar.requestUri The URI where the JAR will be accessible
 * @param input.jar.jwtSigner Function to sign the JAR JWT
 * @param input.jar.jweEncryptor Optional function to encrypt the JAR JWT
 * @param input.jar.additionalJwtPayload Optional additional claims to include in JAR JWT
 * @param input.wallet Optional wallet-specific parameters
 * @param input.wallet.nonce Optional wallet nonce
 * @param input.callbacks Callback functions for JWT operations
 * @returns Object containing the authorization request parameters, URI and optional JAR details
 */
export async function createOpenid4vpAuthorizationRequest(options: CreateOpenid4vpAuthorizationRequestOptions) {
  const { jar, scheme = 'openid4vp://', requestParams, wallet, callbacks } = options

  let additionalJwtPayload: Record<string, unknown> | undefined

  let authRequestParams: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  if (isOpenid4vpAuthorizationRequestDcApi(requestParams)) {
    authRequestParams = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestDcApi,
      requestParams,
      'Invalid authorization request. Could not parse openid4vp dc_api authorization request.'
    )

    if (jar && !authRequestParams.expected_origins) {
      throw new Oauth2Error(
        `The 'expected_origins' parameter MUST be present when using the dc_api response mode in combination with jar.`
      )
    }

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authRequestParams,
      isJarRequest: Boolean(jar),
      omitOriginValidation: true,
    })
  } else {
    authRequestParams = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequest,
      requestParams,
      'Invalid authorization request. Could not parse openid4vp authorization request.'
    )
    validateOpenid4vpAuthorizationRequestPayload({ params: authRequestParams, walletVerificationOptions: wallet })
  }

  if (jar) {
    if (!jar.additionalJwtPayload?.aud) {
      additionalJwtPayload = { ...jar.additionalJwtPayload, aud: jar.requestUri }
    }
  }

  if (jar) {
    const jarResult = await createJarAuthRequest({
      ...jar,
      authRequestParams: requestParams,
      additionalJwtPayload,
      callbacks,
    })

    const url = new URL(scheme)
    url.search = `?${new URLSearchParams([
      ...url.searchParams.entries(),
      ...objectToQueryParams(jarResult.requestParams).entries(),
    ]).toString()}`

    return {
      authRequestObject: jarResult.requestParams,
      authRequest: url.toString(),
      jar: { ...jar, ...jarResult },
    }
  }

  const url = new URL(scheme)
  url.search = `?${new URLSearchParams([
    ...url.searchParams.entries(),
    ...objectToQueryParams(requestParams).entries(),
  ]).toString()}`

  return {
    authRequestObject: requestParams,
    authRequest: url.toString(),
    jar: undefined,
  }
}
