import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { CallbackContext } from '../../../oauth2/src/callbacks'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
} from '../authorization-request/z-authorization-request-dc-api'
import type { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/z-client-metadata'
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
      kid: string
      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'x509_san_dns' | 'x509_san_uri'
      identifier: string
      originalValue: string
      clientMetadata?: ClientMetadata
      x5c: string[]
    }
  | {
      scheme: 'verifier_attestation' | 'pre-registered'
      identifier: string
      originalValue: string
      clientMetadata?: ClientMetadata
    }
  | {
      scheme: 'web-origin'
      identifier?: string
      originalValue?: string
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
  jar?: Awaited<ReturnType<typeof verifyJarRequest>>
  origin?: string
  callbacks: Partial<Pick<CallbackContext, 'getX509CertificateMetadata'>>
}

function getClientId(request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi, origin?: string) {
  const isDcApiRequest = isOpenid4vpAuthorizationRequestDcApi(request)
  if (isDcApiRequest) {
    if (request.client_id) {
      return request.client_id
    }

    if (!origin) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Failed to parse client identifier. Missing required "client_id" parameter.',
      })
    }

    return `web-origin:${origin}`
  }

  return request.client_id
}

/**
 * Parse and validate a client identifier
 */
export function parseClientIdentifier(
  options: ClientIdentifierParserOptions,
  parserConfig?: ClientIdentifierParserConfig
): ParsedClientIdentifier {
  const { request, jar } = options

  const isDcApiRequest = isOpenid4vpAuthorizationRequestDcApi(request)
  const clientId = getClientId(request, options.origin)

  // By default require signatures for these schemes
  const parserConfigWithDefaults: Required<ClientIdentifierParserConfig> = {
    supportedSchemes:
      parserConfig?.supportedSchemes ||
      Object.values(zClientIdScheme.options).filter((scheme) => scheme !== 'web-origin'),
  }

  if (isDcApiRequest && !jar && request.client_id) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'client_id' parameter MUST be omitted in unsigned openid4vp dc api authorization requests.`,
    })
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
    if (isDcApiRequest) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The client identifier scheme 'https' is not supported when using the dc_api response mode.`,
      })
    }

    if (!clientId.startsWith('https://') && !clientId.startsWith('http://')) {
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

    if (isDcApiRequest) {
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
      kid: jar.signer.publicJwk.kid,
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

    if (scheme === 'x509_san_dns' && options.callbacks.getX509CertificateMetadata) {
      const { sanDnsNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanDnsNames.includes(identifierPart)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: 'Invalid client identifier. Client identifier must be a valid DNS name.',
        })
      }

      const requestUri = (jar.authRequestParams.request_uri ?? jar.authRequestParams.response_uri) as string
      if (getDomainFromUrl(requestUri) !== identifierPart) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description:
            'Invalid client identifier. The fully qualified domain name of the redirect_uri value MUST match the Client Identifier without the prefix x509_san_dns.',
        })
      }
    } else if (scheme === 'x509_san_uri' && options.callbacks.getX509CertificateMetadata) {
      const { sanUriNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanUriNames.includes(identifierPart)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: 'Invalid client identifier. Client identifier must be a valid URI.',
        })
      }

      if ((jar.authRequestParams.request_uri ?? jar.authRequestParams.response_uri) !== identifierPart) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: 'The redirect_uri value MUST match the Client Identifier without the prefix x509_san_uri',
        })
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
  const regex = /[#/?]/
  const domain = url.split('://')[1].split(regex)[0]
  return domain
}
