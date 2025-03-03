import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError, getGlobalConfig } from '@openid4vc/oauth2'
import type { CallbackContext } from '../../../oauth2/src/callbacks'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
} from '../authorization-request/z-authorization-request-dc-api'
import type { VerifiedJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/z-client-metadata'
import { parseAuthorizationRequestVersion } from '../version'
import { type ClientIdScheme, zClientIdScheme } from './z-client-id-scheme'

/**
 * Result of parsing a client identifier
 */
export type ParsedClientIdentifier =
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

/**
 * Configuration options for the parser
 */
export interface ClientIdentifierParserConfig {
  supportedSchemes?: ClientIdScheme[]
}

export interface ClientIdentifierParserOptions {
  request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar?: VerifiedJarRequest
  origin?: string
  callbacks: Partial<Pick<CallbackContext, 'getX509CertificateMetadata'>>
}

function getClientId(options: ClientIdentifierParserOptions) {
  if (isOpenid4vpAuthorizationRequestDcApi(options.request)) {
    if (!options.origin) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          "Failed to parse client identifier. 'origin' is required for requests with response_mode 'dc_api' and 'dc_api.jwt'",
      })
    }

    if (!options.jar || !options.request.client_id) return `web-origin:${options.origin}`

    return options.request.client_id
  }

  return options.request.client_id
}

function getLegacyClientId(options: ClientIdentifierParserOptions) {
  const legacyClientIdScheme = options.request.client_id_scheme ?? 'pre-registered'

  let clientIdScheme: ClientIdScheme
  if (legacyClientIdScheme === 'entity_id') {
    clientIdScheme = 'https'
  } else {
    clientIdScheme = legacyClientIdScheme
  }

  if (isOpenid4vpAuthorizationRequestDcApi(options.request)) {
    if (!options.origin) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          "Failed to parse client identifier. 'origin' is required for requests with response_mode 'dc_api' and 'dc_api.jwt'",
      })
    }

    if (!options.jar || !options.request.client_id) return `web-origin:${options.origin}`

    return `${clientIdScheme}:${options.request.client_id}`
  }

  if (clientIdScheme === 'https' || clientIdScheme === 'did') {
    return options.request.client_id
  }

  if (clientIdScheme === 'pre-registered') {
    return options.request.client_id
  }

  return `${clientIdScheme}:${options.request.client_id}`
}

/**
 * Parse and validate a client identifier
 */
export function parseClientIdentifier(
  options: ClientIdentifierParserOptions,
  parserConfig?: ClientIdentifierParserConfig
): ParsedClientIdentifier {
  const { request, jar } = options

  const version = parseAuthorizationRequestVersion(request)
  // this means that client_id_scheme is used
  if (version < 22) {
    const legacyClientIdScheme = request.client_id_scheme ?? 'pre-registered'

    let clientIdSchem: ClientIdScheme
    if (legacyClientIdScheme) {
      if (legacyClientIdScheme === 'entity_id') {
        clientIdSchem = 'https'
      } else {
        clientIdSchem = legacyClientIdScheme
      }
    }
  }

  const isDcApiRequest = isOpenid4vpAuthorizationRequestDcApi(request)
  const clientId = version < 22 ? getLegacyClientId(options) : getClientId(options)

  // By default require signatures for these schemes
  const parserConfigWithDefaults = {
    supportedSchemes: parserConfig?.supportedSchemes || Object.values(zClientIdScheme.options),
  }

  const colonIndex = clientId.indexOf(':')
  if (colonIndex === -1) {
    return {
      scheme: 'pre-registered',
      identifier: clientId,
      originalValue: clientId,
      clientMetadata: request.client_metadata,
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
    // https://github.com/openid/OpenID4VP/issues/436
    if (isDcApiRequest) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The client identifier scheme 'https' is not supported when using the dc_api response mode.`,
      })
    }

    if (!clientId.startsWith('https://') && !(getGlobalConfig().allowInsecureUrls && clientId.startsWith('http://'))) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Invalid client identifier. Client identifier must start with https:// or http:// if allowInsecureUrls is true.',
      })
    }

    return {
      scheme,
      identifier: clientId,
      originalValue: clientId,
      trustChain: request.trust_chain,
    }
  }

  if (scheme === 'redirect_uri') {
    if (jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "redirect_uri" the request MUST NOT be signed.',
      })
    }

    if (isOpenid4vpAuthorizationRequestDcApi(request)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The client identifier scheme 'redirect_uri' is not supported when using the dc_api response mode.`,
      })
    }

    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      redirectUri: (request.redirect_uri ?? request.response_uri) as string,
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

      if (!isOpenid4vpAuthorizationRequestDcApi(request)) {
        const uri = request.redirect_uri ?? request.response_uri
        if (!uri || getDomainFromUrl(uri) !== identifierPart) {
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

      if (!isOpenid4vpAuthorizationRequestDcApi(request)) {
        const uri = request.redirect_uri || request.response_uri
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
      x5c: jar.signer.x5c,
    }
  }

  if (scheme === 'web-origin') {
    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      clientMetadata: request.client_metadata,
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
    originalValue: clientId,
  }
}

function getDomainFromUrl(url: string): string {
  try {
    const regex = /[#/?]/
    const domain = url.split('://')[1].split(regex)[0]
    return domain
  } catch (error) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.ServerError,
      error_description: `Url '${url}' is not a valid URL`,
    })
  }
}
