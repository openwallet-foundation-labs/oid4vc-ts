import { Oauth2Error } from '@openid4vc/oauth2'
import type { CallbackContext } from '../../../oauth2/src/callbacks'
import type { verifyJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/v-client-metadata'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request'
import { type ClientIdScheme, vClientIdScheme } from './v-client-id-scheme'

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
  requireSignatureFor?: ClientIdScheme[]
}

/**
 * Parse and validate a client identifier
 */
export function parseClientIdentifier(
  options: {
    request: Openid4vpAuthRequest
    jar?: Awaited<ReturnType<typeof verifyJarRequest>>
    callbacks: Partial<Pick<CallbackContext, 'getX509SanDnsNames' | 'getX509SanUriNames'>>
  },
  parserConfig?: ClientIdentifierParserConfig
): ParsedClientIdentifier {
  const { request, jar } = options
  const clientId = request.client_id

  if (!clientId?.length) {
    throw new Oauth2Error('Failed to parse client identifier. Client identifier is missing or empty.')
  }

  // By default require signatures for these schemes
  const parserConfigWithDefaults: Required<ClientIdentifierParserConfig> = {
    supportedSchemes:
      parserConfig?.supportedSchemes ||
      Object.values(vClientIdScheme.options).filter((scheme) => scheme !== 'web-origin'),
    requireSignatureFor:
      parserConfig?.requireSignatureFor ||
      ([
        'did',
        'verifier_attestation',
        'x509_san_dns',
        'x509_san_uri',
        'https',
        'pre-registered',
      ] satisfies ClientIdScheme[]),
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
    throw new Oauth2Error(`Unsupported client identifier scheme. ${schemePart} is not supported.`)
  }

  const scheme = schemePart as ClientIdScheme
  if (scheme === 'https') {
    if (!clientId.startsWith('https://') && !clientId.startsWith('http://')) {
      throw new Oauth2Error(
        'Invalid client identifier. Client identifier must start with https:// or http:// if allowInsecureUrls is true.'
      )
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
      throw new Oauth2Error('Using client identifier scheme "redirect_uri" the request MUST NOT be signed.')
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
      throw new Oauth2Error('Using client identifier scheme "did" requires a signed JAR request.')
    }

    if (!clientId.startsWith('did:')) {
      throw new Oauth2Error('Invalid client identifier. Client identifier must start with did:')
    }

    if (!jar.signerJwk.kid) {
      throw new Oauth2Error('Missing required kid for client identifier scheme: did')
    }

    if (!jar?.signerJwk.kid?.startsWith(clientId)) {
      throw new Oauth2Error(
        'With client identifier scheme "did" the JAR request must be signed by the same DID as the client identifier.'
      )
    }

    return {
      scheme,
      identifier: clientId,
      originalValue: clientId,
      kid: jar.signerJwk.kid,
    }
  }

  if (scheme === 'web-origin') {
    throw new Oauth2Error('Unsupported client identifier scheme. web-origin is not supported.')
  }

  if (scheme === 'x509_san_dns' || scheme === 'x509_san_uri') {
    if (!jar) {
      throw new Oauth2Error(
        'Using client identifier scheme "x509_san_dns" or "x509_san_uri" requires a signed JAR request.'
      )
    }

    if (jar.jwtSigner.method !== 'x5c') {
      throw new Oauth2Error(
        'Something went wrong. The JWT signer method is not x5c but the client identifier scheme is x509_san_dns.'
      )
    }

    if (scheme === 'x509_san_dns' && options.callbacks.getX509SanDnsNames) {
      const dnsNames = options.callbacks.getX509SanDnsNames(jar.jwtSigner.x5c[0])
      if (!dnsNames.includes(identifierPart)) {
        throw new Oauth2Error('Invalid client identifier. Client identifier must be a valid DNS name.')
      }
    } else if (scheme === 'x509_san_uri' && options.callbacks.getX509SanUriNames) {
      const uriNames = options.callbacks.getX509SanUriNames(jar.jwtSigner.x5c[0])
      if (!uriNames.includes(identifierPart)) {
        throw new Oauth2Error('Invalid client identifier. Client identifier must be a valid URI.')
      }
    }

    return {
      scheme,
      identifier: identifierPart,
      originalValue: clientId,
      x5c: jar.jwtSigner.x5c,
    }
  }

  if (scheme === 'verifier_attestation') {
    if (!jar) {
      throw new Oauth2Error('Using client identifier scheme "verifier_attestation" requires a signed JAR request.')
    }
  }

  return {
    scheme,
    identifier: identifierPart,
    originalValue: clientId,
  }
}
