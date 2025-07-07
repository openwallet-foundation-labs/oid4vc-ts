import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
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
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Missing required 'redirect_uri' or 'response_uri' in openid4vp authorization request.`,
    })
  }

  if (params.response_uri && !['direct_post', 'direct_post.jwt'].find((mode) => mode === params.response_mode)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'response_mode' parameter MUST be 'direct_post' or 'direct_post.jwt' when 'response_uri' is provided. Current: ${params.response_mode}`,
    })
  }

  if (
    [params.presentation_definition_uri, params.presentation_definition, params.dcql_query, params.scope].filter(
      Boolean
    ).length > 1
  ) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'Exactly one of the following parameters MUST be present in the authorization request: dcql_query, presentation_definition, presentation_definition_uri, or a scope value representing a Presentation Definition.',
    })
  }

  if (params.request_uri_method && !params.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'The "request_uri_method" parameter MUST NOT be present in the authorization request if the "request_uri" parameter is not present.',
    })
  }

  if (params.request_uri_method && !['GET', 'POST'].includes(params.request_uri_method)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestUriMethod,
      error_description: `The 'request_uri_method' parameter MUST be 'GET' or 'POST'. Current: ${params.request_uri_method}`,
    })
  }

  if (params.trust_chain && !zHttpsUrl.safeParse(params.client_id).success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'The "trust_chain" parameter MUST NOT be present in the authorization request if the "client_id" is not an OpenId Federation Entity Identifier starting with http:// or https://.',
    })
  }

  if (walletVerificationOptions?.expectedNonce && !params.wallet_nonce) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'The "wallet_nonce" parameter MUST be present in the authorization request when the "expectedNonce" parameter is provided.',
    })
  }

  if (walletVerificationOptions?.expectedNonce !== params.wallet_nonce) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'The "wallet_nonce" parameter MUST match the "expectedNonce" parameter when the "expectedNonce" parameter is provided.',
    })
  }

  if (params.client_id.startsWith('web-origin:') || params.client_id.startsWith('origin:')) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'client_id' parameter MUST NOT use client identifier scheme '${params.client_id.split(':')[0]}' when not using the dc_api response mode. Current: ${params.client_id}`,
    })
  }
}
