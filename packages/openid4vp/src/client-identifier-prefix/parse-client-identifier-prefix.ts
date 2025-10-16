import {
  type CallbackContext,
  HashAlgorithm,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { decodeBase64, encodeToBase64Url, URL, zHttpsUrl } from '@openid4vc/utils'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import {
  isOpenid4vpAuthorizationRequestDcApi,
  isOpenid4vpResponseModeDcApi,
  type Openid4vpAuthorizationRequestDcApi,
} from '../authorization-request/z-authorization-request-dc-api'
import type { VerifiedJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/z-client-metadata'
import type { Openid4vpVersionNumber } from '../version'
import {
  type ClientIdPrefix,
  type LegacyClientIdScheme,
  type UniformClientIdPrefix,
  zClientIdPrefix,
  zClientIdPrefixToUniform,
  zClientIdToClientIdPrefixAndIdentifier,
  zLegacyClientIdSchemeToClientIdPrefix,
} from './z-client-id-prefix'

type ParsedClientIdentifierBase = {
  /**
   * The effective client identifier, and can be used to create and validate the session binding in e.g. the `aud`
   * of the SD-JWT KB-JWT.
   */
  effective: string

  /**
   * The identifier part of the client id. E.g. `did:example:123` for `decentralized_identifier:did:example:123`
   */
  identifier: string

  /**
   * These are the original raw unvalidated values for the client id. Be cautious with using these.
   */
  original: {
    /**
     * This is the actual `client_id` parameter. May be undefined in case of unsigned
     * DC API request.
     */
    clientId?: string

    /**
     * This is the legacy `client_id_scheme` parameter
     */
    clientIdScheme?: LegacyClientIdScheme
  }
}

/**
 * Result of parsing a client identifier
 */
export type ParsedClientIdentifier = (
  | {
      prefix: 'redirect_uri'
      redirectUri: string
      clientMetadata?: ClientMetadata
    }
  | {
      prefix: 'openid_federation'
      trustChain?: unknown
      clientMetadata?: never // clientMetadata must be obtained from the entity statement
    }
  | {
      prefix: 'decentralized_identifier'
      didUrl: string
      clientMetadata?: ClientMetadata
    }
  | {
      prefix: 'x509_san_uri' | 'x509_san_dns' | 'x509_hash'
      clientMetadata?: ClientMetadata
      x5c: string[]
    }
  | {
      prefix: 'verifier_attestation' | 'pre-registered' | 'origin'
      clientMetadata?: ClientMetadata
    }
) &
  ParsedClientIdentifierBase

export interface GetOpenid4vpClientIdOptions {
  /**
   * The client_id. Could be undefined in case of DC API
   */
  clientId?: string

  /**
   * Legacy client id scheme from the authorization request payload
   */
  legacyClientIdScheme?: unknown

  responseMode: unknown
  origin?: string

  /**
   * The version of OpenID4VP used.
   *
   * Currently it is only used for:
   * - determining whether effective client id is `origin:` or `web-origin:` when DC API is used.
   *
   * When no version is provided, it is assumed version 1.0 (100) is used.
   */
  version?: Openid4vpVersionNumber
}

/**
 * Get the client id for an authorization request based on the response_mode, client_id, client_id_scheme and origin values.
 *
 * It will return the client id prefix as used in OpenID4VP v1, and optionally provide the legacyClientId if the
 * client id was provided with a client_id_scheme
 */
export function getOpenid4vpClientId(options: GetOpenid4vpClientIdOptions): {
  /**
   * The identifier part of the client id. E.g. `did:example:123`, or `https://federation.com`
   */
  clientIdIdentifier: string

  /**
   * The client id prefix according to the latest verion of OpenID4VP. Older prefixes are
   * transformed into a singular value. Do not use this for checking the actual client id prefix
   * used, but can be used to understand which method is used.
   *
   * E.g. `did` will be put as `decentralized_identifier`
   */
  clientIdPrefix: UniformClientIdPrefix

  /**
   * The effective client id prefix, is the client id prefix that was used in the actual request.
   *
   * E.g. `did` will remain as `did`
   */
  effectiveClientIdPrefix: ClientIdPrefix | LegacyClientIdScheme

  /**
   * The effective client id is the client id that should be used for validation. E.g. if you're comparing
   * the `aud` claim in a SD-JWT KB-JWT, this is the value where you should match against.
   */
  effectiveClientId: string

  /**
   * These are the original raw unvalidated values for the client id
   */
  original: {
    /**
     * This is the actual `client_id` parameter. May be undefined in case of unsigned
     * DC API request.
     */
    clientId?: string

    /**
     * This is the legacy `client_id_scheme` parameter
     */
    clientIdScheme?: LegacyClientIdScheme
  }
} {
  const original = {
    clientId: options.clientId,
  }

  const version = options.version ?? 100

  // Handle DC API
  if (isOpenid4vpResponseModeDcApi(options.responseMode)) {
    if (!options.clientId) {
      if (!options.origin) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description:
            "Failed to parse client identifier. 'origin' is required for requests without a client_id and response_mode 'dc_api' and 'dc_api.jwt'",
        })
      }

      return {
        clientIdPrefix: 'origin',
        effectiveClientIdPrefix: 'origin',
        clientIdIdentifier: options.origin,
        effectiveClientId: version >= 25 ? `origin:${options.origin}` : `web-origin:${options.origin}`,
        original,
      }
    }

    const parsedClientIdPrefixAndIdentifier = zClientIdToClientIdPrefixAndIdentifier.safeParse(options.clientId)
    if (!parsedClientIdPrefixAndIdentifier.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
      })
    }

    const [clientIdScheme, clientIdIdentifier] = parsedClientIdPrefixAndIdentifier.data
    const uniformClientIdScheme = zClientIdPrefixToUniform.safeParse(clientIdScheme)
    if (!uniformClientIdScheme.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
      })
    }

    return {
      effectiveClientId: options.clientId,
      effectiveClientIdPrefix: clientIdScheme,
      original,

      clientIdPrefix: uniformClientIdScheme.data,
      clientIdIdentifier,
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
    const parsedClientIdPrefix = zLegacyClientIdSchemeToClientIdPrefix.safeParse(options.legacyClientIdScheme)
    if (!parsedClientIdPrefix.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id_scheme value '${options.legacyClientIdScheme}'.`,
      })
    }

    const clientIdPrefix = parsedClientIdPrefix.data

    return {
      effectiveClientId: options.clientId,
      clientIdIdentifier: options.clientId,
      clientIdPrefix,
      effectiveClientIdPrefix: (options.legacyClientIdScheme ?? 'pre-registered') as LegacyClientIdScheme,
      original: {
        ...original,
        clientIdScheme: options.legacyClientIdScheme as LegacyClientIdScheme | undefined,
      },
    }
  }

  const parsedClientIdPrefixAndIdentifier = zClientIdToClientIdPrefixAndIdentifier.safeParse(options.clientId)
  if (!parsedClientIdPrefixAndIdentifier.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
    })
  }

  const [clientIdScheme, clientIdIdentifier] = parsedClientIdPrefixAndIdentifier.data
  const uniformClientIdScheme = zClientIdPrefixToUniform.safeParse(clientIdScheme)
  if (!uniformClientIdScheme.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
    })
  }

  // Fall back to modern client id. We don't validate it yet, we just want to get the
  // modern client id
  return {
    effectiveClientId: options.clientId,
    clientIdPrefix: uniformClientIdScheme.data,
    effectiveClientIdPrefix: clientIdScheme,
    clientIdIdentifier,
    original,
  }
}

/**
 * Configuration options for the parser
 */
export interface ValidateOpenid4vpClientIdParserConfig {
  supportedSchemes?: UniformClientIdPrefix[]
}

export interface ValidateOpenid4vpClientIdOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar?: VerifiedJarRequest
  origin?: string
  callbacks: Pick<CallbackContext, 'getX509CertificateMetadata' | 'hash'>

  version: Openid4vpVersionNumber
}

/**
 * Parse and validate a client identifier
 */
export async function validateOpenid4vpClientId(
  options: ValidateOpenid4vpClientIdOptions,
  parserConfig?: ValidateOpenid4vpClientIdParserConfig
): Promise<ParsedClientIdentifier> {
  const { authorizationRequestPayload, jar, origin } = options

  // By default require signatures for these schemes
  const parserConfigWithDefaults = {
    supportedSchemes: parserConfig?.supportedSchemes || Object.values(zClientIdPrefix.options),
  }

  const { clientIdIdentifier, clientIdPrefix, effectiveClientId, original } = getOpenid4vpClientId({
    clientId: authorizationRequestPayload.client_id,
    legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
    responseMode: authorizationRequestPayload.response_mode,
    origin,
  })

  if (clientIdPrefix === 'pre-registered') {
    return {
      prefix: 'pre-registered',
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
    }
  }

  if (!parserConfigWithDefaults.supportedSchemes.includes(clientIdPrefix)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Unsupported client identifier prefix. ${clientIdPrefix} is not supported.`,
    })
  }

  if (clientIdPrefix === 'openid_federation') {
    if (!zHttpsUrl.safeParse(clientIdIdentifier).success) {
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

    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier prefix "https" requires a signed JAR request.',
      })
    }

    if (jar.signer.method !== 'federation') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Something went wrong. The JWT signer method is not federation but the client identifier prefix is https.',
      })
    }

    return {
      prefix: 'openid_federation',
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
      trustChain: authorizationRequestPayload.trust_chain,
    }
  }

  if (clientIdPrefix === 'redirect_uri') {
    if (jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier prefix "redirect_uri" the request MUST NOT be signed.',
      })
    }

    if (isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The client identifier prefix 'redirect_uri' is not supported when using the dc_api response mode.`,
      })
    }

    if (authorizationRequestPayload.redirect_uri && authorizationRequestPayload.redirect_uri !== clientIdIdentifier) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidClient,
        error_description: `When the client identifier prefix is 'redirect_uri', the client id identifier MUST match the redirect_uri.`,
      })
    }

    if (authorizationRequestPayload.response_uri && authorizationRequestPayload.response_uri !== clientIdIdentifier) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidClient,
        error_description: `When the client identifier prefix is 'redirect_uri', the client id identifier MUST match the response_uri.`,
      })
    }

    return {
      prefix: clientIdPrefix,
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
      clientMetadata: authorizationRequestPayload.client_metadata,
      redirectUri: (authorizationRequestPayload.redirect_uri ?? authorizationRequestPayload.response_uri) as string,
    }
  }

  if (clientIdPrefix === 'decentralized_identifier') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier prefix "did" requires a signed JAR request.',
      })
    }

    if (jar.signer.method !== 'did') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Something went wrong. The JWT signer method is not did but the client identifier prefix is did.',
      })
    }

    if (!clientIdIdentifier.startsWith('did:')) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: "Invalid client identifier. Client id identifier must start with 'did:'",
      })
    }

    const [did] = jar.signer.didUrl.split('#')
    if (clientIdIdentifier !== did) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `With client identifier prefix '${clientIdPrefix}' the JAR request must be signed by the same DID as the client identifier.`,
      })
    }

    return {
      prefix: 'decentralized_identifier',
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
      clientMetadata: authorizationRequestPayload.client_metadata,
      didUrl: jar.signer.didUrl,
    }
  }

  if (clientIdPrefix === 'x509_san_dns' || clientIdPrefix === 'x509_san_uri' || clientIdPrefix === 'x509_hash') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Using client identifier prefix '${clientIdPrefix}' requires a signed JAR request.`,
      })
    }

    if (jar.signer.method !== 'x5c') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Something went wrong. The JWT signer method is not x5c but the client identifier prefix is '${clientIdPrefix}'`,
      })
    }

    if (!options.callbacks.getX509CertificateMetadata) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.ServerError,
        },
        {
          internalMessage: `Missing required 'getX509CertificateMetadata' callback for verification of '${clientIdPrefix}' client id prefix`,
        }
      )
    }

    if (clientIdPrefix === 'x509_san_dns') {
      const { sanDnsNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanDnsNames.includes(clientIdIdentifier)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. One of the leaf certificates san dns names [${sanDnsNames.join(', ')}] must match the client identifier '${clientIdIdentifier}'. `,
        })
      }

      if (!isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
        const uri = authorizationRequestPayload.redirect_uri ?? authorizationRequestPayload.response_uri
        if (!uri || new URL(uri).hostname !== clientIdIdentifier) {
          throw new Oauth2ServerErrorResponseError({
            error: Oauth2ErrorCodes.InvalidRequest,
            error_description:
              'Invalid client identifier. The fully qualified domain name of the redirect_uri value MUST match the Client Identifier without the prefix x509_san_dns.',
          })
        }
      }
    } else if (clientIdPrefix === 'x509_san_uri') {
      const { sanUriNames } = options.callbacks.getX509CertificateMetadata(jar.signer.x5c[0])
      if (!sanUriNames.includes(clientIdIdentifier)) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. One of the leaf certificates san uri names [${sanUriNames.join(', ')}] must match the client identifier '${clientIdIdentifier}'.`,
        })
      }

      if (!isOpenid4vpAuthorizationRequestDcApi(authorizationRequestPayload)) {
        const uri = authorizationRequestPayload.redirect_uri || authorizationRequestPayload.response_uri
        if (!uri || uri !== clientIdIdentifier) {
          throw new Oauth2ServerErrorResponseError({
            error: Oauth2ErrorCodes.InvalidRequest,
            error_description:
              'The redirect_uri value MUST match the Client Identifier without the prefix x509_san_uri',
          })
        }
      }
    } else if (clientIdPrefix === 'x509_hash') {
      const x509Hash = encodeToBase64Url(
        await options.callbacks.hash(decodeBase64(jar.signer.x5c[0]), HashAlgorithm.Sha256)
      )

      if (x509Hash !== clientIdIdentifier) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. Expected the base64url encoded sha-256 hash of the leaf x5c certificate ('${x509Hash}') to match the client identifier '${clientIdIdentifier}'.`,
        })
      }
    }

    return {
      prefix: clientIdPrefix,
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
      x5c: jar.signer.x5c,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }

  if (clientIdPrefix === 'origin') {
    return {
      prefix: clientIdPrefix,
      identifier: clientIdIdentifier,
      effective: effectiveClientId,
      original,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }

  if (clientIdPrefix === 'verifier_attestation') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier prefix "verifier_attestation" requires a signed JAR request.',
      })
    }
  }

  return {
    prefix: clientIdPrefix,
    clientMetadata: authorizationRequestPayload.client_metadata,
    identifier: clientIdIdentifier,
    effective: effectiveClientId,
    original,
  }
}
