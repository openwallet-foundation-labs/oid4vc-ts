import type { CallbackContext, JwtSigner } from '@openid4vc/oauth2'
import { uriEncodeObject } from '@openid4vc/utils'
import { createJarAuthRequest } from '../jar/create-jar-auth-request'
import type { Openid4vpAuthRequest } from './v-openid4vp-auth-request'
import { validateOpenid4vpAuthRequestParams } from './validate-openid4vp-auth-request'

/**
 * Creates an OpenID4VP authorization request, optionally with a JWT Secured Authorization Request (JAR)
 * If the request is created after receiving wallet metadata via a POST to the request_uri endpoint, the wallet nonce needs to be provided
 *
 * @param input Configuration options for creating the authorization request
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
export async function createOpenid4vpAuthorizationRequest(input: {
  scheme?: string
  requestParams: Openid4vpAuthRequest
  jar?: {
    requestUri: string
    jwtSigner: JwtSigner
    jweEncryptor?: JwtSigner
    additionalJwtPayload?: Record<string, unknown>
  }
  wallet?: {
    nonce?: string
  }
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}) {
  const { jar, scheme: _scheme, requestParams, wallet, callbacks } = input
  const scheme = _scheme ?? 'openid4vp://'

  validateOpenid4vpAuthRequestParams(requestParams, { wallet: wallet })

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

    return {
      authRequestParams: jarResult.requestParams,
      uri: `${scheme}?${uriEncodeObject(jarResult.requestParams)}`,
      jar: { ...jar, ...jarResult },
    }
  }

  return {
    authRequestParams: requestParams,
    uri: `${scheme}?${uriEncodeObject(requestParams)}`,
    jar: undefined,
  }
}
