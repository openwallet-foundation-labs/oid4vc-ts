import type { CallbackContext, JwtSigner } from '@openid4vc/oauth2'
import { URL, URLSearchParams, objectToQueryParams } from '@openid4vc/utils'
import { createJarAuthRequest } from '../jar/create-jar-auth-request'
import {
  type WalletVerificationOptions,
  validateOpenid4vpAuthorizationRequestPayload,
} from './validate-authorization-request'
import type { Openid4vpAuthorizationRequest } from './z-authorization-request'

export interface CreateOpenid4vpAuthorizationRequestOptions {
  scheme?: string
  requestParams: Openid4vpAuthorizationRequest
  jar?: {
    requestUri: string
    jwtSigner: JwtSigner
    jweEncryptor?: JwtSigner
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

  validateOpenid4vpAuthorizationRequestPayload({ params: requestParams, walletVerificationOptions: wallet })

  let additionalJwtPayload: Record<string, unknown> | undefined

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
