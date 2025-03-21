import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { URL, zHttpsUrl } from '@openid4vc/utils'
import type { CallbackContext } from '../../../oauth2/src/callbacks'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  isOpenid4vpResponseModeDcApi,
} from '../authorization-request/z-authorization-request-dc-api'
import type { VerifiedJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/z-client-metadata'
import { type ClientIdScheme, zClientIdScheme, zLegacyClientIdScheme } from './z-client-id-scheme'

/**
 * Result of parsing a client identifier
 */
export type ParsedClientIdentifier = (
  | {
      scheme: 'redirect_uri'
      identifier: string
      originalValue: string
      redirectUri: string

      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'https'
      identifier: string
      originalValue: string
      trustChain?: unknown
      clientMetadata?: never // clientMetadata must be obtained from the entity statement
    }
  | {
      scheme: 'did'
      identifier: string
      originalValue: string
      didUrl: string
      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'x509_san_uri' | 'x509_san_dns'
      identifier: string
      originalValue: string
      clientMetadata?: ClientMetadata
      x5c: string[]
    }
  | {
      scheme: 'verifier_attestation' | 'pre-registered' | 'web-origin'
      identifier: string
      originalValue: string
      clientMetadata?: ClientMetadata
    }
) & {
  /**
   * Optional legacy client id value, if client_id_scheme was used.
   * Most credential formats require the client id to be included in the presentation.
   */
  legacyClientId?: string
}

export interface GetOpenid4vpClientIdOptions {
  responseMode: Openid4vpAuthorizationRequestDcApi['response_mode'] | Openid4vpAuthorizationRequest['response_mode']
  clientId?: string
  legacyClientIdScheme?: string
  origin?: string
}

/**
 * Get the client id for an authorization request based on the response_mode, client_id, client_id_scheme and origin values.
 *
 * It will return the client id scheme as used in OpenID4VP draft 24, and optionally provide the legacyClientId if the
 * client id was provided with a client_id_scheme
 */
export function getOpenid4vpClientId(options: GetOpenid4vpClientIdOptions) {
  // Handle DC API
  if (isOpenid4vpResponseModeDcApi(options.responseMode)) {
    if (options.legacyClientIdScheme) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. response_mode '${options.responseMode}' is not supported in combination with 'client_id_scheme'`,
      })
    }

    if (!options.origin) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          "Failed to parse client identifier. 'origin' is required for requests with response_mode 'dc_api' and 'dc_api.jwt'",
      })
    }

    return {
      clientId: options.clientId ?? `web-origin:${options.origin}`,
    }
  }

  // If no DC API, client_id is required
  if (!options.clientId) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Failed to parse client identifier. Missing required client_id parameter for response_mode '${options.responseMode}'.`,
    })
  }

  // Handle legacy client id scheme
  if (options.legacyClientIdScheme) {
    const parsedClientIdScheme = zLegacyClientIdScheme.safeParse(options.legacyClientIdScheme)
    if (!parsedClientIdScheme.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id_scheme value '${options.legacyClientIdScheme}'.`,
      })
    }

    const clientIdScheme = parsedClientIdScheme.data === 'entity_id' ? 'https' : parsedClientIdScheme.data
    if (clientIdScheme === 'https' || clientIdScheme === 'did' || clientIdScheme === 'pre-registered') {
      return { clientId: options.clientId }
    }

    return {
      clientId: `${clientIdScheme}:${options.clientId}`,
      legacyClientId: options.clientId,
    }
  }

  // Fall back to modern client id. We don't validate it yet, we just want to get the
  // modern client id
  return {
    clientId: options.clientId,
  }
}

/**
 * Configuration options for the parser
 */
export interface ClientIdentifierParserConfig {
  supportedSchemes?: ClientIdScheme[]
}

export interface ClientIdentifierParserOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar?: VerifiedJarRequest
  origin?: string
  callbacks: Partial<Pick<CallbackContext, 'getX509CertificateMetadata'>>
}

/**
 * Parse and validate a client identifier
 */
export function parseClientIdentifier(
  options: ClientIdentifierParserOptions,
  parserConfig?: ClientIdentifierParserConfig
): ParsedClientIdentifier {
  const { authorizationRequestPayload, jar } = options

  // By default require signatures for these schemes
  const parserConfigWithDefaults = {
    supportedSchemes: parserConfig?.supportedSchemes || Object.values(zClientIdScheme.options),
  }

  const { clientId, legacyClientId } = getOpenid4vpClientId({
    responseMode: authorizationRequestPayload.response_mode,
    clientId: authorizationRequestPayload.client_id,
    legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
  })

  const colonIndex = clientId.indexOf(':')
  if (colonIndex === -1) {
    return {
      scheme: 'pre-registered',
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }

  const schemePart = clientId.substring(0, colonIndex)
  const identifierPart = clientId.substring(colonIndex + 1)

  if (!parserConfigWithDefaults.supportedSchemes.includes(schemePart as ClientIdScheme)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Unsupported client identifier scheme. ${schemePart} is not supported.`,
    })
  }

  const scheme = schemePart as ClientIdScheme
  if (scheme === 'https') {
    if (!zHttpsUrl.safeParse(clientId).success) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: 'Invalid client identifier. Client identifier must start with https://',
        },
        {
          internalMessage: `Insecure http:// urls can be enabled by setting the 'allowInsecureUrls' option using setGlobalConfig`,
        }
      )
    }

    return {
      scheme,
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      trustChain: authorizationRequestPayload.trust_chain,
    }
  }

  if (scheme === 'redirect_uri') {
    if (jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "redirect_uri" the request MUST NOT be signed.',
      })
    }

    if (isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The client identifier scheme 'redirect_uri' is not supported when using the dc_api response mode.`,
      })
    }

    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      redirectUri: (authorizationRequestPayload.redirect_uri ?? authorizationRequestPayload.response_uri) as string,
    }
  }

  if (scheme === 'did') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "did" requires a signed JAR request.',
      })
    }

    if (!clientId.startsWith('did:')) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: "Invalid client identifier. Client identifier must start with 'did:'",
      })
    }

    if (!jar.signer.publicJwk.kid) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Missing required 'kid' for client identifier scheme: did`,
      })
    }

    if (!jar.signer.publicJwk.kid?.startsWith(clientId)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'With client identifier scheme "did" the JAR request must be signed by the same DID as the client identifier.',
      })
    }

    return {
      scheme,
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      didUrl: jar.signer.publicJwk.kid,
    }
  }

  if (scheme === 'x509_san_dns' || scheme === 'x509_san_uri') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Using client identifier scheme "x509_san_dns" or "x509_san_uri" requires a signed JAR request.',
      })
    }

    if (jar.signer.method !== 'x5c') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Something went wrong. The JWT signer method is not x5c but the client identifier scheme is x509_san_dns.',
      })
    }

    if (scheme === 'x509_san_dns') {
      if (!options.callbacks.getX509CertificateMetadata) {
        throw new Oauth2ServerErrorResponseError(
          {
            error: Oauth2ErrorCodes.ServerError,
          },
          {
            internalMessage:
              "Missing required 'getX509CertificateMetadata' callback for verification of 'x509_san_dns' client id scheme",
          }
        )
      }

      const { sanDnsNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanDnsNames.includes(identifierPart)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. One of the leaf certificates san dns names [${sanDnsNames.join(', ')}] must match the client identifier '${identifierPart}'. `,
        })
      }

      if (!isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
        const uri = authorizationRequestPayload.redirect_uri ?? authorizationRequestPayload.response_uri
        if (!uri || new URL(uri).hostname !== identifierPart) {
          throw new Oauth2ServerErrorResponseError({
            error: Oauth2ErrorCodes.InvalidRequest,
            error_description:
              'Invalid client identifier. The fully qualified domain name of the redirect_uri value MUST match the Client Identifier without the prefix x509_san_dns.',
          })
        }
      }
    } else if (scheme === 'x509_san_uri') {
      if (!options.callbacks.getX509CertificateMetadata) {
        throw new Oauth2ServerErrorResponseError(
          {
            error: Oauth2ErrorCodes.ServerError,
          },
          {
            internalMessage:
              "Missing required 'getX509CertificateMetadata' callback for verification of 'x509_san_uri' client id scheme",
          }
        )
      }

      const { sanUriNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanUriNames.includes(identifierPart)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. One of the leaf certificates san uri names [${sanUriNames.join(', ')}] must match the client identifier '${identifierPart}'.`,
        })
      }

      if (!isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
        const uri = authorizationRequestPayload.redirect_uri || authorizationRequestPayload.response_uri
        if (!uri || uri !== identifierPart) {
          throw new Oauth2ServerErrorResponseError({
            error: Oauth2ErrorCodes.InvalidRequest,
            error_description:
              'The redirect_uri value MUST match the Client Identifier without the prefix x509_san_uri',
          })
        }
      }
    }

    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      x5c: jar.signer.x5c,
    }
  }

  if (scheme === 'web-origin') {
    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }

  if (scheme === 'verifier_attestation') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "verifier_attestation" requires a signed JAR request.',
      })
    }
  }

  return {
    scheme,
    identifier: identifierPart,
    legacyClientId,
    originalValue: clientId,
  }
}
