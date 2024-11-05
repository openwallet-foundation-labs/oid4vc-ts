import * as v from 'valibot'

import {
  type CallbackContext,
  ContentType,
  Oauth2ClientErrorResponseError,
  Oauth2Error,
  Oauth2InvalidFetchResponseError,
  type RequestDpopOptions,
  resourceRequestWithDpopRetry,
} from '@animo-id/oauth2'
import { ValidationError, createValibotFetcher, parseWithErrorHandling } from '@animo-id/oauth2-utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Oid4vciDraftVersion } from '../version'
import {
  type CredentialRequest,
  type CredentialRequestWithFormats,
  vCredentialRequest,
  vCredentialRequestDraft14To11,
} from './v-credential-request'
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

  return retrieveCredentials({
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

/**
 * internal method
 */
async function retrieveCredentials(options: RetrieveCredentialsOptions) {
  const fetchWithValibot = createValibotFetcher(options.callbacks.fetch)
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.credential_endpoint

  let credentialRequest = parseWithErrorHandling(
    vCredentialRequest,
    options.credentialRequest,
    'Error validating credential request'
  )

  if (credentialRequest.proofs) {
    const { batch_credential_issuance } = options.issuerMetadata.credentialIssuer
    if (!batch_credential_issuance) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer}' does not support batch credential issuance using the 'proofs' request property. Only 'proof' is supported.`
      )
    }

    const proofs = Object.values(credentialRequest.proofs)[0]
    if (proofs.length > batch_credential_issuance.batch_size) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer}' supports batch issuance, but the max batch size is '${batch_credential_issuance.batch_size}'. A total of '${proofs.length}' proofs were provided.`
      )
    }
  }

  if (options.issuerMetadata.originalDraftVersion === Oid4vciDraftVersion.Draft11) {
    credentialRequest = parseWithErrorHandling(
      vCredentialRequestDraft14To11,
      credentialRequest,
      `Error transforming credential request from ${Oid4vciDraftVersion.Draft14} to ${Oid4vciDraftVersion.Draft11}`
    )
  }

  const { dpop, result } = await resourceRequestWithDpopRetry({
    dpop: options.dpop ? { ...options.dpop, request: { method: 'POST', url: credentialEndpoint } } : undefined,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    resourceRequest: async ({ headers }) => {
      const { response, result } = await fetchWithValibot(vCredentialResponse, credentialEndpoint, {
        body: JSON.stringify(credentialRequest),
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': ContentType.Json,
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
          throw new Oauth2ClientErrorResponseError(
            `Unable to retrieve credentials from '${credentialEndpoint}'. Received response with status ${response.status}`,
            credentialErrorResponse.output,
            response
          )
        }

        throw new Oauth2InvalidFetchResponseError(
          `Unable to retrieve credentials from '${credentialEndpoint}'. Received response with status ${response.status}`,
          await response.clone().text(),
          response
        )
      }

      if (!result.success) {
        throw new ValidationError('Error validating credential response', result.issues)
      }

      return {
        response,
        result: result.output,
      }
    },
  })

  return {
    dpop,
    credentialResponse: result,
  }
}