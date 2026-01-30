import {
  type CallbackContext,
  type CreateJarAuthorizationRequestOptions,
  createJarAuthorizationRequest,
} from '@openid4vc/oauth2'
import { objectToQueryParams, parseWithErrorHandling, URL, URLSearchParams } from '@openid4vc/utils'
import {
  validateOpenid4vpAuthorizationRequestPayload,
  type WalletVerificationOptions,
} from './validate-authorization-request'
import { validateOpenid4vpAuthorizationRequestDcApiPayload } from './validate-authorization-request-dc-api'
import { validateOpenid4vpAuthorizationRequestIaePayload } from './validate-authorization-request-iae'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'
import {
  isOpenid4vpAuthorizationRequestDcApi,
  type Openid4vpAuthorizationRequestDcApi,
  zOpenid4vpAuthorizationRequestDcApi,
} from './z-authorization-request-dc-api'
import {
  isOpenid4vpAuthorizationRequestIae,
  type Openid4vpAuthorizationRequestIae,
  zOpenid4vpAuthorizationRequestIae,
} from './z-authorization-request-iae'

export interface CreateOpenid4vpAuthorizationRequestOptions {
  scheme?: string
  authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  jar?: Pick<
    CreateJarAuthorizationRequestOptions,
    'additionalJwtPayload' | 'requestUri' | 'jwtSigner' | 'expiresInSeconds'
  >

  wallet?: WalletVerificationOptions
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>

  /**
   * Date that should be used as now. If not provided current date will be used.
   */
  now?: Date
}

/**
 * Creates an OpenID4VP authorization request, optionally with a JWT Secured Authorization Request (JAR)
 * If the request is created after receiving wallet metadata via a POST to the request_uri endpoint, the wallet nonce needs to be provided
 *
 * @param options Configuration options for creating the authorization request
 * @param input.scheme Optional URI scheme to use (defaults to 'openid4vp://')
 * @param input.authorizationRequestPayload The OpenID4VP authorization request parameters
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
  const { jar, scheme = 'openid4vp://', wallet, callbacks } = options

  let additionalJwtPayload: Record<string, unknown> | undefined

  let authorizationRequestPayload:
    | Openid4vpAuthorizationRequest
    | Openid4vpAuthorizationRequestDcApi
    | Openid4vpAuthorizationRequestIae
  if (isOpenid4vpAuthorizationRequestDcApi(options.authorizationRequestPayload)) {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestDcApi,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp dc_api authorization request.'
    )

    validateOpenid4vpAuthorizationRequestDcApiPayload({
      params: authorizationRequestPayload,
      isJarRequest: Boolean(jar),
      disableOriginValidation: true,
    })
  } else if (isOpenid4vpAuthorizationRequestIae(options.authorizationRequestPayload)) {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequestIae,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp iae_post authorization request.'
    )

    validateOpenid4vpAuthorizationRequestIaePayload({
      params: authorizationRequestPayload,
      isJarRequest: Boolean(jar),
      disableExpectedUrlValidation: true,
    })
  } else {
    authorizationRequestPayload = parseWithErrorHandling(
      zOpenid4vpAuthorizationRequest,
      options.authorizationRequestPayload,
      'Invalid authorization request. Could not parse openid4vp authorization request.'
    )
    validateOpenid4vpAuthorizationRequestPayload({
      params: authorizationRequestPayload,
      walletVerificationOptions: wallet,
    })
  }

  if (jar) {
    additionalJwtPayload = !jar.additionalJwtPayload?.aud
      ? { ...jar.additionalJwtPayload, aud: jar.requestUri }
      : jar.additionalJwtPayload

    const jarResult = await createJarAuthorizationRequest({
      ...jar,
      authorizationRequestPayload,
      additionalJwtPayload,
      callbacks,
    })

    const url = new URL(scheme)
    url.search = `?${new URLSearchParams([
      ...url.searchParams.entries(),
      ...objectToQueryParams(jarResult.jarAuthorizationRequest).entries(),
      // Add client_id_scheme if defined for backwards compat
      ...(authorizationRequestPayload.client_id_scheme
        ? [['client_id_scheme', authorizationRequestPayload.client_id_scheme]]
        : []),
    ]).toString()}`

    return {
      authorizationRequestPayload,
      authorizationRequestObject: jarResult.jarAuthorizationRequest,
      authorizationRequest: url.toString(),
      jar: { ...jar, ...jarResult },
    }
  }

  const url = new URL(scheme)
  url.search = `?${new URLSearchParams([
    ...url.searchParams.entries(),
    ...objectToQueryParams(authorizationRequestPayload).entries(),
  ]).toString()}`

  return {
    authorizationRequestPayload,
    authorizationRequestObject: authorizationRequestPayload,
    authorizationRequest: url.toString(),
    jar: undefined,
  }
}
