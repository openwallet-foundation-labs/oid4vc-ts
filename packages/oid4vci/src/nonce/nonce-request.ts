import { InvalidFetchResponseError } from '@openid4vc/oauth2'
import { ContentType, type Fetch, ValidationError, createZodFetcher, parseWithErrorHandling } from '@openid4vc/utils'
import { Oid4vciError } from '../error/Oid4vciError'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { type NonceResponse, zNonceResponse } from './z-nonce'

export interface RequestNonceOptions {
  issuerMetadata: IssuerMetadataResult

  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch
}

/**
 * Request a nonce from the `nonce_endpoint`
 *
 * @throws Oid4vciError - if no `nonce_endpoint` is configured in the issuer metadata
 * @thrwos InvalidFetchResponseError - if the nonce endpoint did not return a succesfull response
 * @throws ValidationError - if validating the nonce response failed
 */
export async function requestNonce(options: RequestNonceOptions): Promise<NonceResponse> {
  const fetchWithZod = createZodFetcher(options?.fetch)
  const nonceEndpoint = options.issuerMetadata.credentialIssuer.nonce_endpoint

  if (!nonceEndpoint) {
    throw new Oid4vciError(
      `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not have a nonce endpoint.`
    )
  }

  const { response, result } = await fetchWithZod(zNonceResponse, ContentType.Json, nonceEndpoint, {
    method: 'POST',
  })

  if (!response.ok || !result) {
    throw new InvalidFetchResponseError(
      `Requesting nonce from '${nonceEndpoint}' resulted in an unsuccesfull response with status '${response.status}'`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new ValidationError('Error parsing nonce response', result.error)
  }

  return result.data
}

export interface CreateNonceResponseOptions {
  cNonce: string
  cNonceExpiresIn?: number

  /**
   * Additional payload to include in the nonce response.
   *
   * Will be applied after default params to allow extension so be cautious
   */
  additionalPayload?: Record<string, unknown>
}

export function createNonceResponse(options: CreateNonceResponseOptions) {
  return parseWithErrorHandling(zNonceResponse, {
    c_nonce: options.cNonce,
    c_nonce_expires_in: options.cNonceExpiresIn,
    ...options.additionalPayload,
  } satisfies NonceResponse)
}
