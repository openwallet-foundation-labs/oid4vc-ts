import * as v from 'valibot'
import { ContentType } from '../common/content-type'
import { parseWithErrorHandling } from '../common/validation/parse'
import { Oid4vcError } from '../error/Oid4vcError'
import { Oid4vcInvalidFetchResponseError } from '../error/Oid4vcInvalidFetchResponseError'
import { Oid4vcOauthErrorResponseError } from '../error/Oid4vcOauthErrorResponseError'
import { Oid4vcValidationError } from '../error/Oid4vcValidationError'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { type Fetch, createValibotFetcher } from '../utils/valibot-fetcher'
import { type CredentialRequest, type CredentialRequestFormats, vCredentialRequest } from './v-credential-request'
import type { CredentialRequestProof, CredentialRequestProofs } from './v-credential-request-common'
import { vCredentialErrorResponse, vCredentialResponse } from './v-credential-response'

export interface RetrieveCredentialsWithFormatOptions {
  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The format specific payload. Needs to at least include the `format` and other params
   * are determined by the format itself
   */
  formatPayload: CredentialRequestFormats

  proof?: CredentialRequestProof
  proofs?: CredentialRequestProofs

  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string
}

export async function retrieveCredentialsWithFormat(options: RetrieveCredentialsWithFormatOptions) {
  const credentialRequest: CredentialRequest = {
    ...options.formatPayload,
    ...options.additionalRequestPayload,

    proof: options.proof,
    proofs: options.proofs,
  }

  return retrieveCredentials({
    fetch: options.fetch,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
  })
}

export interface RetrieveCredentialsOptions {
  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * The credential request
   */
  credentialRequest: CredentialRequest

  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string
}

/**
 * internal method
 */
async function retrieveCredentials(options: RetrieveCredentialsOptions) {
  const fetchWithValibot = createValibotFetcher(options.fetch)
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

  const { response, result } = await fetchWithValibot(vCredentialResponse, credentialEndpoint, {
    body: JSON.stringify(credentialRequest),
    method: 'POST',
    headers: {
      Authorization: `Bearer ${options.accessToken}`,
      'Content-Type': ContentType.Json,
    },
  })

  if (!response.ok || !result) {
    const credentialErrorResponse = v.safeParse(vCredentialErrorResponse, await response.clone().json())
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

  // TODO: probably good to also return the response? At least status / headers
  return result.output
}
