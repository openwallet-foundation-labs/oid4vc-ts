import * as v from 'valibot'
import { type RequestDpopOptions, createDpopJwt, extractDpopNonceFromHeaders } from '../authorization/dpop/dpop'
import { shouldRetryResourceRequestWithDPoPNonce } from '../authorization/dpop/dpop-retry'
import type { CallbackContext } from '../callbacks'
import { ContentType } from '../common/content-type'
import { parseWithErrorHandling } from '../common/validation/parse'
import { Oid4vcError } from '../error/Oid4vcError'
import { Oid4vcInvalidFetchResponseError } from '../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../error/Oid4vcOauthErrorResponseError'
import { Oid4vcValidationError } from '../error/Oid4vcValidationError'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { createValibotFetcher } from '../utils/valibot-fetcher'
import { type CredentialRequest, type CredentialRequestWithFormats, vCredentialRequest } from './v-credential-request'
import type { CredentialRequestProof, CredentialRequestProofs } from './v-credential-request-common'
import { vCredentialErrorResponse, vCredentialResponse } from './v-credential-response'

interface RetrieveCredentialsBaseOptions {
  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Callback used in retrieve credentials endpoints
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJwt'>

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string

  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions
}

export interface RetrieveCredentialsWithFormatOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The format specific payload. Needs to at least include the `format` and other params
   * are determined by the format itself
   */
  formatPayload: CredentialRequestWithFormats

  proof?: CredentialRequestProof
  proofs?: CredentialRequestProofs
}

export async function retrieveCredentialsWithFormat(options: RetrieveCredentialsWithFormatOptions) {
  const credentialRequest: CredentialRequest = {
    ...options.formatPayload,
    ...options.additionalRequestPayload,

    proof: options.proof,
    proofs: options.proofs,
  }

  return retrieveCredentialsWithDpopRetry({
    callbacks: options.callbacks,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
    dpop: options.dpop,
  })
}

export interface RetrieveCredentialsOptions extends RetrieveCredentialsBaseOptions {
  /**
   * The credential request
   */
  credentialRequest: CredentialRequest
}

async function retrieveCredentialsWithDpopRetry(options: RetrieveCredentialsOptions) {
  try {
    return await retrieveCredentials(options)
  } catch (error) {
    if (
      options.dpop &&
      (error instanceof Oid4vcInvalidFetchResponseError || error instanceof Oid4vcOauthErrorResponseError)
    ) {
      const dpopRetry = shouldRetryResourceRequestWithDPoPNonce({
        responseHeaders: error.response.headers,
      })

      // Retry with the dpop nonce
      if (dpopRetry.retry) {
        return retrieveCredentials({
          ...options,
          dpop: {
            ...options.dpop,
            nonce: dpopRetry.dpopNonce,
          },
        })
      }
    }

    throw error
  }
}

/**
 * internal method
 */
async function retrieveCredentials(options: RetrieveCredentialsOptions) {
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.credential_endpoint

  const credentialRequest = parseWithErrorHandling(
    vCredentialRequest,
    options.credentialRequest,
    'Error validating credential request'
  )

  if (credentialRequest.proofs) {
    if (!options.issuerMetadata.credentialIssuer.batch_credential_issuance) {
      throw new Oid4vcError(
        `Credential issuer '${options.issuerMetadata.credentialIssuer}' does not support batch credential issuance using the 'proofs' request property. Only 'proof' is supported.`
      )
    }

    // TODO: add batch_size validation
  }

  const dpopJwt = options.dpop
    ? await createDpopJwt({
        httpMethod: 'POST',
        requestUri: credentialEndpoint,
        signer: options.dpop.signer,
        callbacks: options.callbacks,
        nonce: options.dpop.nonce,
        accessToken: options.accessToken,
      })
    : undefined

  const { response, result } = await fetchWithValibot(vCredentialResponse, credentialEndpoint, {
    body: JSON.stringify(credentialRequest),
    method: 'POST',
    headers: {
      Authorization: `${dpopJwt ? 'DPoP' : 'Bearer'} ${options.accessToken}`,
      'Content-Type': ContentType.Json,
      ...(dpopJwt ? { DPoP: dpopJwt } : {}),
    },
  })

  if (!response.ok || !result) {
    const credentialErrorResponse = v.safeParse(
      vCredentialErrorResponse,
      await response
        .clone()
        .json()
        .catch(() => null)
    )
    if (credentialErrorResponse.success) {
      throw new Oid4vcOauthErrorResponseError(
        `Unable to retrieve credentials from '${credentialEndpoint}'. Received response with status ${response.status}`,
        credentialErrorResponse.output,
        response
      )
    }

    throw new Oid4vcInvalidFetchResponseError(
      `Unable to retrieve credentials from '${credentialEndpoint}'. Received response with status ${response.status}`,
      await response.clone().text(),
      response
    )
  }

  if (!result.success) {
    throw new Oid4vcValidationError('Error validating credential response', result.issues)
  }

  const dpopNonce = extractDpopNonceFromHeaders(response.headers)
  return {
    dpop: dpopNonce
      ? {
          nonce: dpopNonce,
        }
      : undefined,
    credentialResponse: result.output,
  }
}
