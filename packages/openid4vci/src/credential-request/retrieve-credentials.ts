import {
  type CallbackContext,
  Oauth2Error,
  type RequestDpopOptions,
  type ResourceRequestResponseNotOk,
  type ResourceRequestResponseOk,
  resourceRequest,
  type zOauth2ErrorResponse,
} from '@openid4vc/oauth2'
import {
  ContentType,
  type FetchResponse,
  isResponseContentType,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from '@openid4vc/utils'
import type z from 'zod'
import { Openid4vciError } from '../error/Openid4vciError'
import { getKnownCredentialConfigurationSupportedById } from '../metadata/credential-issuer/credential-issuer-metadata'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Openid4vciVersion } from '../version'
import {
  type CredentialRequest,
  type CredentialRequestWithFormats,
  zCredentialRequest,
  zCredentialRequestDraft14To11,
  zDeferredCredentialRequest,
} from './z-credential-request'
import type {
  CredentialRequestProof,
  CredentialRequestProofs,
  CredentialResponseEncryption,
} from './z-credential-request-common'
import {
  type CredentialResponse,
  type DeferredCredentialResponse,
  zCredentialErrorResponse,
  zCredentialResponse,
  zDeferredCredentialResponse,
} from './z-credential-response'

/**
 * Handles credential response by detecting content type, decrypting if needed, and parsing.
 * Returns the parsed JSON payload or throws/returns error state.
 */
async function handleCredentialResponse<T, Schema extends z.ZodType<T>>(options: {
  response: FetchResponse
  decryptJwe: CallbackContext['decryptJwe']
  credentialResponseEncryption?: CredentialResponseEncryption
  schema: Schema
  errorContext: string
}): Promise<{ ok: true; data: T } | { ok: false; parseResult: ReturnType<Schema['safeParse']> | undefined }> {
  const { response, decryptJwe, credentialResponseEncryption, schema, errorContext } = options

  // Check if the response is encrypted (Content-Type: application/jwt)
  if (isResponseContentType(ContentType.Jwt, response)) {
    const jwe = await response.clone().text()
    const decryptResult = await decryptJwe(jwe)

    if (!decryptResult.decrypted) {
      return { ok: false, parseResult: undefined }
    }

    const jsonPayload = stringToJsonWithErrorHandling(
      decryptResult.payload,
      `Unable to parse decrypted ${errorContext} as JSON`
    )
    const parseResult = schema.safeParse(jsonPayload) as ReturnType<Schema['safeParse']>

    if (!parseResult.success) {
      return { ok: false, parseResult }
    }

    return { ok: true, data: parseResult.data }
  }

  // If encryption was requested but response is not encrypted, that's an error
  if (credentialResponseEncryption) {
    throw new Openid4vciError(
      `Encryption was requested via 'credential_response_encryption' but the ${errorContext} was not encrypted. ` +
        `Expected Content-Type 'application/jwt' but received '${response.headers.get('Content-Type')}'.`
    )
  }

  // Try to parse the response (non-encrypted)
  const parseResult = (
    isResponseContentType(ContentType.Json, response) ? schema.safeParse(await response.clone().json()) : undefined
  ) as ReturnType<Schema['safeParse']> | undefined

  if (!parseResult?.success) {
    return { ok: false, parseResult }
  }

  return { ok: true, data: parseResult.data }
}

interface RetrieveCredentialsBaseOptions {
  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult

  /**
   * Callbacks used in retrieve credentials endpoints.
   */
  callbacks: Pick<CallbackContext, 'fetch' | 'generateRandom' | 'hash' | 'signJwt' | 'decryptJwe'>

  /**
   * Access token authorized to retrieve the credential(s)
   */
  accessToken: string

  /**
   * DPoP options
   */
  dpop?: RequestDpopOptions

  /**
   * Request encryption of the credential response. When provided, the client
   * includes `credential_response_encryption` in the request and expects
   * an encrypted JWE response.
   *
   * The `decryptJwe` callback must be provided to decrypt the response.
   */
  credentialResponseEncryption?: CredentialResponseEncryption
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
  if (
    options.issuerMetadata.originalDraftVersion !== Openid4vciVersion.Draft15 &&
    options.issuerMetadata.originalDraftVersion !== Openid4vciVersion.V1
  ) {
    throw new Openid4vciError(
      'Requesting credentials based on credential configuration ID is not supported in OpenID4VCI below draft 15. Make sure to provide the format and format specific claims in the request.'
    )
  }

  // This ensures the credential configuration exists
  getKnownCredentialConfigurationSupportedById(options.issuerMetadata, options.credentialConfigurationId)

  const credentialRequest: CredentialRequest = {
    ...options.additionalRequestPayload,

    credential_configuration_id: options.credentialConfigurationId,
    proof: options.proof,
    proofs: options.proofs,
    credential_response_encryption: options.credentialResponseEncryption,
  }

  return retrieveCredentials({
    callbacks: options.callbacks,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
    dpop: options.dpop,
    credentialResponseEncryption: options.credentialResponseEncryption,
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
  if (
    options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft15 ||
    options.issuerMetadata.originalDraftVersion === Openid4vciVersion.V1
  ) {
    throw new Openid4vciError(
      'Requesting credentials based on format is not supported on OpenID4VCI above draft 15. Provide the credential configuration id directly in the request.'
    )
  }

  const credentialRequest: CredentialRequest = {
    ...options.formatPayload,
    ...options.additionalRequestPayload,

    proof: options.proof,
    proofs: options.proofs,
    credential_response_encryption: options.credentialResponseEncryption,
  }

  return retrieveCredentials({
    callbacks: options.callbacks,
    credentialRequest,
    issuerMetadata: options.issuerMetadata,
    accessToken: options.accessToken,
    dpop: options.dpop,
    credentialResponseEncryption: options.credentialResponseEncryption,
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
   * The successful validated (in structure, not the actual contents are validated) credential response payload
   */
  credentialResponse: CredentialResponse
}

export interface RetrieveCredentialsResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response itself was successful but the validation of the
   * credential response data structure failed
   */
  credentialResponseResult?: ReturnType<typeof zCredentialResponse.safeParse>

  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a credential error response. It may be successful or it may not be.
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
    if (options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft11) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not support batch credential issuance using the 'proofs' request property. Only 'proof' is supported.`
      )
    }

    const proofs = Object.values(credentialRequest.proofs)[0]
    if (proofs.length > (batch_credential_issuance?.batch_size ?? 1)) {
      throw new Oauth2Error(
        `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' supports batch issuance, but the max batch size is '${batch_credential_issuance?.batch_size ?? 1}'. A total of '${proofs.length}' proofs were provided.`
      )
    }
  }

  if (options.issuerMetadata.originalDraftVersion === Openid4vciVersion.Draft11) {
    credentialRequest = parseWithErrorHandling(
      zCredentialRequestDraft14To11,
      credentialRequest,
      `Error transforming credential request from ${Openid4vciVersion.Draft14} to ${Openid4vciVersion.Draft11}`
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

  const result = await handleCredentialResponse<CredentialResponse, typeof zCredentialResponse>({
    response: resourceResponse.response,
    decryptJwe: options.callbacks.decryptJwe,
    credentialResponseEncryption: options.credentialResponseEncryption,
    schema: zCredentialResponse,
    errorContext: 'credential response',
  })

  if (!result.ok) {
    return {
      ...resourceResponse,
      ok: false,
      credentialResponseResult: result.parseResult,
    }
  }

  return {
    ...resourceResponse,
    credentialResponse: result.data,
  }
}

export interface RetrieveDeferredCredentialsOptions extends RetrieveCredentialsBaseOptions {
  /**
   * Additional payload to include in the credential request.
   */
  additionalRequestPayload?: Record<string, unknown>

  /**
   * The transaction ID
   */
  transactionId: string
}

export interface RetrieveDeferredCredentialsResponseOk extends ResourceRequestResponseOk {
  /**
   * The successful validated (in structure, not the actual contents are validated) deferred credential response payload
   */
  deferredCredentialResponse: DeferredCredentialResponse
}

export interface RetrieveDeferredCredentialsResponseNotOk extends ResourceRequestResponseNotOk {
  /**
   * If this is defined it means the response itself was successful but the validation of the
   * credential response data structure failed
   */
  deferredCredentialResponseResult?: ReturnType<typeof zDeferredCredentialResponse.safeParse>

  /**
   * If this is defined it means the response was JSON and we tried to parse it as
   * a credential error response. It may be successful or it may not be.
   */
  deferredCredentialErrorResponseResult?: ReturnType<typeof zOauth2ErrorResponse.safeParse>
}

export async function retrieveDeferredCredentials(
  options: RetrieveDeferredCredentialsOptions
): Promise<RetrieveDeferredCredentialsResponseNotOk | RetrieveDeferredCredentialsResponseOk> {
  const credentialEndpoint = options.issuerMetadata.credentialIssuer.deferred_credential_endpoint
  if (!credentialEndpoint) {
    throw new Openid4vciError(
      `Credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}' does not support deferred credential retrieval.`
    )
  }

  const deferredCredentialRequest = parseWithErrorHandling(
    zDeferredCredentialRequest,
    {
      transaction_id: options.transactionId,
      credential_response_encryption: options.credentialResponseEncryption,
      ...options.additionalRequestPayload,
    },
    'Error validating deferred credential request'
  )

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
      body: JSON.stringify(deferredCredentialRequest),
    },
  })

  if (!resourceResponse.ok) {
    const deferredCredentialErrorResponseResult = isResponseContentType(ContentType.Json, resourceResponse.response)
      ? zCredentialErrorResponse.safeParse(await resourceResponse.response.clone().json())
      : undefined

    return {
      ...resourceResponse,
      deferredCredentialErrorResponseResult,
    }
  }

  const deferredResponseSchema = zDeferredCredentialResponse.refine(
    (response) => response.credentials || response.transaction_id === options.transactionId,
    {
      message: `Transaction id in deferred credential response does not match transaction id in deferred credential request '${options.transactionId}'`,
    }
  )

  const result = await handleCredentialResponse<DeferredCredentialResponse, typeof deferredResponseSchema>({
    response: resourceResponse.response,
    decryptJwe: options.callbacks.decryptJwe,
    credentialResponseEncryption: options.credentialResponseEncryption,
    schema: deferredResponseSchema,
    errorContext: 'deferred credential response',
  })

  if (!result.ok) {
    return {
      ...resourceResponse,
      ok: false,
      deferredCredentialResponseResult: result.parseResult,
    }
  }

  return {
    ...resourceResponse,
    deferredCredentialResponse: result.data,
  }
}
