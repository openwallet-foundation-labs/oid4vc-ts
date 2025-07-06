import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { type CallbackContext, HashAlgorithm } from '@openid4vc/oauth2'
import { URL, decodeBase64, encodeToBase64Url, zHttpsUrl } from '@openid4vc/utils'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import {
  type Openid4vpAuthorizationRequestDcApi,
  isOpenid4vpAuthorizationRequestDcApi,
  isOpenid4vpResponseModeDcApi,
} from '../authorization-request/z-authorization-request-dc-api'
import type { VerifiedJarRequest } from '../jar/handle-jar-request/verify-jar-request'
import type { ClientMetadata } from '../models/z-client-metadata'
import {
  type ClientIdScheme,
  zClientIdScheme,
  zClientIdToClientIdScheme,
  zLegacyClientIdSchemeToClientIdScheme,
} from './z-client-id-scheme'

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
      scheme: 'x509_san_uri' | 'x509_san_dns' | 'x509_hash'
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
}

/**
 * Get the client id for an authorization request based on the response_mode, client_id, client_id_scheme and origin values.
 *
 * It will return the client id scheme as used in OpenID4VP draft 24, and optionally provide the legacyClientId if the
 * client id was provided with a client_id_scheme
 */
export function getOpenid4vpClientId(options: GetOpenid4vpClientIdOptions): {
  clientId: string
  clientIdScheme: ClientIdScheme
  legacyClientId?: string
} {
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
        clientIdScheme: 'web-origin',
        clientId: `web-origin:${options.origin}`,
      }
    }

    const parsedClientIdScheme = zClientIdToClientIdScheme.safeParse(options.clientId)
    if (!parsedClientIdScheme.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
      })
    }

    return {
      clientId: options.clientId,
      clientIdScheme: parsedClientIdScheme.data,
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
    const parsedClientIdScheme = zLegacyClientIdSchemeToClientIdScheme.safeParse(options.legacyClientIdScheme)
    if (!parsedClientIdScheme.success) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to parse client identifier. Unsupported client_id_scheme value '${options.legacyClientIdScheme}'.`,
      })
    }

    const clientIdScheme = parsedClientIdScheme.data

    return {
      clientId:
        clientIdScheme === 'https' || clientIdScheme === 'did' || clientIdScheme === 'pre-registered'
          ? options.clientId
          : `${parsedClientIdScheme.data}:${options.clientId}`,
      clientIdScheme: parsedClientIdScheme.data,
      legacyClientId: options.clientId,
    }
  }

  const parsedClientIdScheme = zClientIdToClientIdScheme.safeParse(options.clientId)
  if (!parsedClientIdScheme.success) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Failed to parse client identifier. Unsupported client_id '${options.clientId}'.`,
    })
  }

  // Fall back to modern client id. We don't validate it yet, we just want to get the
  // modern client id
  return {
    clientId: options.clientId,
    clientIdScheme: parsedClientIdScheme.data,
  }
}

/**
 * Configuration options for the parser
 */
export interface ValidateOpenid4vpClientIdParserConfig {
  supportedSchemes?: ClientIdScheme[]
}

export interface ValidateOpenid4vpClientIdOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  jar?: VerifiedJarRequest
  origin?: string
  callbacks: Pick<CallbackContext, 'getX509CertificateMetadata' | 'hash'>
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
    supportedSchemes: parserConfig?.supportedSchemes || Object.values(zClientIdScheme.options),
  }

  const { clientId, legacyClientId, clientIdScheme } = getOpenid4vpClientId({
    clientId: authorizationRequestPayload.client_id,
    legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
    responseMode: authorizationRequestPayload.response_mode,
    origin,
  })

  if (clientIdScheme === 'pre-registered') {
    return {
      scheme: 'pre-registered',
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }
  const colonIndex = clientId.indexOf(':')
  const identifierPart = clientId.substring(colonIndex + 1)

  if (!parserConfigWithDefaults.supportedSchemes.includes(clientIdScheme)) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Unsupported client identifier scheme. ${clientIdScheme} is not supported.`,
    })
  }

  if (clientIdScheme === 'https') {
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

    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "https" requires a signed JAR request.',
      })
    }

    if (jar.signer.method !== 'federation') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Something went wrong. The JWT signer method is not federation but the client identifier scheme is https.',
      })
    }

    return {
      scheme: clientIdScheme,
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      trustChain: authorizationRequestPayload.trust_chain,
    }
  }

  if (clientIdScheme === 'redirect_uri') {
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
      scheme: clientIdScheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      redirectUri: (authorizationRequestPayload.redirect_uri ?? authorizationRequestPayload.response_uri) as string,
    }
  }

  if (clientIdScheme === 'did') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "did" requires a signed JAR request.',
      })
    }

    if (jar.signer.method !== 'did') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'Something went wrong. The JWT signer method is not did but the client identifier scheme is did.',
      })
    }

    if (!clientId.startsWith('did:')) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: "Invalid client identifier. Client identifier must start with 'did:'",
      })
    }

    const [did] = jar.signer.didUrl.split('#')
    if (clientId !== did) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description:
          'With client identifier scheme "did" the JAR request must be signed by the same DID as the client identifier.',
      })
    }

    return {
      scheme: clientIdScheme,
      identifier: clientId,
      originalValue: clientId,
      legacyClientId,
      didUrl: jar.signer.didUrl,
    }
  }

  if (clientIdScheme === 'x509_san_dns' || clientIdScheme === 'x509_san_uri' || clientIdScheme === 'x509_hash') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Using client identifier scheme '${clientIdScheme}' requires a signed JAR request.`,
      })
    }

    if (jar.signer.method !== 'x5c') {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Something went wrong. The JWT signer method is not x5c but the client identifier scheme is '${clientIdScheme}'`,
      })
    }

    if (!options.callbacks.getX509CertificateMetadata) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.ServerError,
        },
        {
          internalMessage: `Missing required 'getX509CertificateMetadata' callback for verification of '${clientIdScheme}' client id scheme`,
        }
      )
    }

    if (clientIdScheme === 'x509_san_dns') {
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
    } else if (clientIdScheme === 'x509_san_uri') {
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
    } else if (clientIdScheme === 'x509_hash') {
      const x509Hash = encodeToBase64Url(
        await options.callbacks.hash(decodeBase64(jar.signer.x5c[0]), HashAlgorithm.Sha256)
      )

      if (x509Hash !== identifierPart) {
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidRequest,
          error_description: `Invalid client identifier. Expected the base64url encoded sha-256 hash of the leaf x5c certificate ('${x509Hash}') to match the client identifier '${identifierPart}'.`,
        })
      }
    }

    return {
      scheme: clientIdScheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      x5c: jar.signer.x5c,
    }
  }

  if (clientIdScheme === 'web-origin') {
    return {
      scheme: clientIdScheme,
      identifier: identifierPart,
      originalValue: clientId,
      legacyClientId,
      clientMetadata: authorizationRequestPayload.client_metadata,
    }
  }

  if (clientIdScheme === 'verifier_attestation') {
    if (!jar) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Using client identifier scheme "verifier_attestation" requires a signed JAR request.',
      })
    }
  }

  return {
    scheme: clientIdScheme,
    identifier: identifierPart,
    legacyClientId,
    originalValue: clientId,
  }
}
