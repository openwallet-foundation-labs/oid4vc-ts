import {
  type CallbackContext,
  Oauth2Error,
  type RequestDpopOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
  resourceRequest,
} from '@openid4vc/oauth2'
import { ContentType, isResponseContentType, parseWithErrorHandling } from '@openid4vc/utils'
import { Openid4vciError } from '../error/Openid4vciError'
import { getCredentialConfigurationSupportedById } from '../metadata/credential-issuer/credential-issuer-metadata'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciDraftVersion } from '../version'
import {
  type CredentialRequest,
  type CredentialRequestWithFormats,
  zCredentialRequest,
  zCredentialRequestDraft14To11,
} from './z-credential-request'
import type { CredentialRequestProof, CredentialRequestProofs } from './z-credential-request-common'
import { type CredentialResponse, zCredentialErrorResponse, zCredentialResponse } from './z-credential-response'

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

export interface RetrieveCredentialsWithCredentialConfigurationIdOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The credential configuration id to request
   */
  credentialConfigurationId: string

  proof?: CredentialRequestProof
  proofs?: CredentialRequestProofs
}

export async function retrieveCredentialsWithCredentialConfigurationId(
  options: RetrieveCredentialsWithCredentialConfigurationIdOptions
) {
  if (options.issuerMetadata.originalDraftVersion !== Openid4vciDraftVersion.Draft15) {
    throw new Openid4vciError(
      'Requesting credentials based on format is not supported in OpenID4VCI below draft 15. Make sure to provide the format and format specific claims in the request.'
    )
  }

  // This ensures the credential configuration exists
  getCredentialConfigurationSupportedById(
    options.issuerMetadata.credentialIssuer.credential_configurations_supported,
    options.credentialConfigurationId
  )

  const credentialRequest: CredentialRequest = {
    ...options.additionalRequestPayload,

    credential_configuration_id: options.credentialConfigurationId,
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
  if (options.issuerMetadata.originalDraftVersion === Openid4vciDraftVersion.Draft15) {
    throw new Openid4vciError(
      'Requesting credentials based on format is not supported in OpenID4VCI draft 15. Provide the credential configuration id directly in the request.'
    )
  }

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

export interface RetrieveCredentialsResponseOk extends ResourceRequestResponseOk {
  /**
   * The successfull validated (in structure, not the actual contents are validated) credential response payload
   */
  credentialResponse: CredentialResponse
}

export interface RetrieveCredentialsResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response itself was succesfull but the validation of the
   * credential response data structure failed
   */
  credentialResponseResult?: ReturnType<typeof zCredentialResponse.safeParse>

  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a credential error response. It may be successfull or it may not be.
   */
  credentialErrorResponseResult?: ReturnType<typeof zCredentialErrorResponse.safeParse>
}

/**
 * internal method
 */
async function retrieveCredentials(
  options: RetrieveCredentialsOptions
): Promise<RetrieveCredentialsResponseNotOk | RetrieveCredentialsResponseOk> {
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.credential_endpoint

  let credentialRequest = parseWithErrorHandling(
    zCredentialRequest,
    options.credentialRequest,
    'Error validating credential request'
  )

  if (credentialRequest.proofs) {
    const { batch_credential_issuance } = options.issuerMetadata.credentialIssuer
    if (!batch_credential_issuance) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not support batch credential issuance using the 'proofs' request property. Only 'proof' is supported.`
      )
    }

    const proofs = Object.values(credentialRequest.proofs)[0]
    if (proofs.length > batch_credential_issuance.batch_size) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' supports batch issuance, but the max batch size is '${batch_credential_issuance.batch_size}'. A total of '${proofs.length}' proofs were provided.`
      )
    }
  }

  if (options.issuerMetadata.originalDraftVersion === Openid4vciDraftVersion.Draft11) {
    credentialRequest = parseWithErrorHandling(
      zCredentialRequestDraft14To11,
      credentialRequest,
      `Error transforming credential request from ${Openid4vciDraftVersion.Draft14} to ${Openid4vciDraftVersion.Draft11}`
    )
  }

  const resourceResponse = await resourceRequest({
    dpop: options.dpop,
    accessToken: options.accessToken,
    callbacks: options.callbacks,
    url: credentialEndpoint,
    requestOptions: {
      method: 'POST',
      headers: {
        'Content-Type': ContentType.Json,
      },
      body: JSON.stringify(credentialRequest),
    },
  })

  if (!resourceResponse.ok) {
    const credentialErrorResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
      ? zCredentialErrorResponse.safeParse(await resourceResponse.response.clone().json())
      : undefined

    return {
      ...resourceResponse,
      credentialErrorResponseResult,
    }
  }

  // Try to parse the credential response
  const credentialResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
    ? zCredentialResponse.safeParse(await resourceResponse.response.clone().json())
    : undefined
  if (!credentialResponseResult?.success) {
    return {
      ...resourceResponse,
      ok: false,
      credentialResponseResult,
    }
  }

  return {
    ...resourceResponse,
    credentialResponse: credentialResponseResult.data,
  }
}
