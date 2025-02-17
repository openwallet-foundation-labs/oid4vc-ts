import { Oauth2Error } from '@openid4vc/oauth2'
import { zHttpsUrl } from '@openid4vc/utils'
import type { WalletMetadata } from '../models/z-wallet-metadata'
import type { Openid4vpAuthorizationRequest } from './z-authorization-request'

export interface WalletVerificationOptions {
  expectedNonce?: string
  metadata?: WalletMetadata
}

export interface ValidateOpenid4vpAuthorizationRequestPayloadOptions {
  params: Openid4vpAuthorizationRequest
  walletVerificationOptions?: WalletVerificationOptions
}

/**
 * Validate the OpenId4Vp Authorization Request parameters
 */
export const validateOpenid4vpAuthorizationRequestPayload = (
  options: ValidateOpenid4vpAuthorizationRequestPayloadOptions
) => {
  const { params, walletVerificationOptions } = options

  if (!params.redirect_uri && !params.response_uri) {
    throw new Oauth2Error('OpenId4Vp Authorization Request redirect_uri or response_uri is required.')
  }

  if (params.response_uri && !['direct_post', 'direct_post.jwt'].find((mode) => mode === params.response_mode)) {
    throw new Oauth2Error(
      `OpenId4Vp Authorization Request response_mode must be direct_post or direct_post.jwt when response_uri is provided. Current: ${params.response_mode}`
    )
  }

  if (
    [params.presentation_definition_uri, params.presentation_definition, params.dcql_query, params.scope].filter(
      Boolean
    ).length > 1
  ) {
    throw new Oauth2Error(
      'Exactly one of the following parameters MUST be present in the Authorization Request: dcql_query, presentation_definition, presentation_definition_uri, or a scope value representing a Presentation Definition.'
    )
  }

  if (params.request_uri_method && !params.request_uri) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request request_uri_method parameter MUST NOT be present if the request_uri parameter is not present.'
    )
  }

  if (params.trust_chain && !zHttpsUrl.safeParse(params.client_id).success) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request trust_chain parameter MUST NOT be present if the client_id is not an OpenId Federation Entity Identifier starting with http:// or https://.'
    )
  }

  if (walletVerificationOptions?.expectedNonce && !params.wallet_nonce) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request wallet_nonce parameter is required when wallet_nonce is provided.'
    )
  }

  if (walletVerificationOptions?.expectedNonce !== params.wallet_nonce) {
    throw new Oauth2Error(
      'OpenId4Vp Authorization Request wallet_nonce parameter does not match the wallet_nonce value passed by the Wallet.'
    )
  }

  if (params.client_id.startsWith('web-origin:')) {
    throw new Oauth2Error(
      `The 'client_id' parameter MUST NOT start with 'web-origin:' when not using the dc_api response mode.`
    )
  }
}
