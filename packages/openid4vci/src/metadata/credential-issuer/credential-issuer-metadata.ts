import {
  type CallbackContext,
  type DecodeJwtResult,
  decodeJwt,
  fetchWellKnownMetadata,
  type JwtSignerWithJwk,
  jwtSignerFromJwt,
  Oauth2Error,
  verifyJwt,
  zCompactJwt,
} from '@openid4vc/oauth2'
import { ContentType, joinUriParts, parseWithErrorHandling, URL } from '@openid4vc/utils'
import type { CredentialFormatIdentifier } from '../../formats/credential'
import type { Openid4vciDraftVersion } from '../../version'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'
import {
  allCredentialIssuerMetadataFormatIdentifiers,
  type CredentialConfigurationSupportedWithFormats,
  type CredentialConfigurationsSupported,
  type CredentialConfigurationsSupportedWithFormats,
  type CredentialIssuerMetadata,
  zCredentialConfigurationSupportedWithFormats,
  zCredentialIssuerMetadataWithDraftVersion,
} from './z-credential-issuer-metadata'
import {
  zSignedCredentialIssuerMetadataHeader,
  zSignedCredentialIssuerMetadataPayload,
} from './z-signed-credential-issuer-metadata'

const wellKnownCredentialIssuerSuffix = '.well-known/openid-credential-issuer'

export interface FetchCredentialIssuerMetadataOptions {
  /**
   * Callbacks for fetching the credential issur metadata.
   * If no `verifyJwt` callback is provided, the request
   * will not include the `application/jwt` Accept header
   * for signed metadata.
   */
  callbacks?: Partial<Pick<CallbackContext, 'fetch' | 'verifyJwt'>>

  /**
   * Only used for verifying signed issuer metadata. If not provided
   * current time will be used
   */
  now?: Date
}

export interface CredentialIssuerMetadataSigned {
  jwt: DecodeJwtResult<typeof zSignedCredentialIssuerMetadataHeader, typeof zSignedCredentialIssuerMetadataPayload>
  signer: JwtSignerWithJwk
}

export interface FetchCredentialIssuerMetadataReturn {
  /**
   * The credential issuer metadata, optionally transformed to Draft 14+ syntax
   */
  credentialIssuerMetadata: CredentialIssuerMetadata

  /**
   * The original draft version of the credential issuer metadata
   */
  originalDraftVersion: Openid4vciDraftVersion

  /**
   * Metadata about the signed issuer metadata, if the metadata was signed.
   */
  signed?: CredentialIssuerMetadataSigned
}

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchCredentialIssuerMetadata(
  credentialIssuer: string,
  options?: FetchCredentialIssuerMetadataOptions
): Promise<FetchCredentialIssuerMetadataReturn | null> {
  const parsedIssuerUrl = new URL(credentialIssuer)

  const legacyWellKnownMetadataUrl = joinUriParts(credentialIssuer, [wellKnownCredentialIssuerSuffix])
  const wellKnownMetadataUrl = joinUriParts(parsedIssuerUrl.origin, [
    wellKnownCredentialIssuerSuffix,
    parsedIssuerUrl.pathname,
  ])

  // If verify jwt callback is provided, we accept both signed and unsigned issuer metadata
  const acceptedContentType: [ContentType, ...ContentType[]] = options?.callbacks?.verifyJwt
    ? [ContentType.Jwt, ContentType.Json]
    : [ContentType.Json]

  // Either unsigned metadata or signed JWT
  const responseSchema = zCredentialIssuerMetadataWithDraftVersion.or(zCompactJwt)

  let result = null
  let firstError = null

  try {
    result = await fetchWellKnownMetadata(wellKnownMetadataUrl, responseSchema, {
      fetch: options?.callbacks?.fetch,
      acceptedContentType,
    })
  } catch (err) {
    // An exception occurs if a CORS-policy blocks the request, i.e. because the URL is invalid due to the legacy path being used
    // The legacy path should still be tried therefore we store the first error to rethrow it later if needed
    firstError = err
  }

  // If the metadata is not available at the new URL, fetch it at the legacy URL
  // The legacy url is the same if no subpath is used by the issuer
  if (!result && legacyWellKnownMetadataUrl !== wellKnownMetadataUrl) {
    try {
      result = await fetchWellKnownMetadata(legacyWellKnownMetadataUrl, responseSchema, {
        fetch: options?.callbacks?.fetch,
        acceptedContentType,
      })
    } catch (err) {
      // If the first attempt also errored, rethrow that original error; otherwise rethrow this one
      throw firstError ?? err
    }
  }

  let issuerMetadataWithVersion: FetchCredentialIssuerMetadataReturn | null = null

  if (typeof result === 'string') {
    // We won't reach this, as we already handle this with accepted content types.
    // Mainly to make TS happy
    if (!options?.callbacks?.verifyJwt) {
      throw new Oauth2Error(
        `Unable to verify signed credential issuer metadata, no 'verifyJwt' callback provided to fetch credential issuer metadata method.`
      )
    }
    const { header, payload, signature } = decodeJwt({
      jwt: result,
      headerSchema: zSignedCredentialIssuerMetadataHeader,
      payloadSchema: zSignedCredentialIssuerMetadataPayload,
    })

    if (payload.sub !== credentialIssuer) {
      throw new Oauth2Error(
        `The 'sub' parameter '${payload.sub}' in the signed well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
      )
    }

    // Extract signer of the JWT
    const signer = jwtSignerFromJwt({ header, payload })

    const verifyResult = await verifyJwt({
      compact: result,
      header,
      payload,
      verifyJwtCallback: options.callbacks.verifyJwt,
      now: options.now,
      signer,
      errorMessage: 'signed credential issuer metadata jwt verification failed',
    })

    const issuerMetadata = parseWithErrorHandling(
      zCredentialIssuerMetadataWithDraftVersion,
      payload,
      'Unable to determine version for signed issuer metadata'
    )

    issuerMetadataWithVersion = {
      ...issuerMetadata,
      signed: {
        signer: verifyResult.signer,
        jwt: {
          header,
          payload,
          signature,
          compact: result,
        },
      },
    }
  } else if (result) {
    issuerMetadataWithVersion = result
  }

  // credential issuer param MUST match
  if (
    issuerMetadataWithVersion &&
    issuerMetadataWithVersion.credentialIssuerMetadata.credential_issuer !== credentialIssuer
  ) {
    throw new Oauth2Error(
      `The 'credential_issuer' parameter '${issuerMetadataWithVersion.credentialIssuerMetadata.credential_issuer}' in the well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return issuerMetadataWithVersion
}

/**
 * Extract credential configuration supported entries where the `format` is known to this
 * library and the configuration validates correctly. Should be ran only after verifying
 * the credential issuer metadata structure, so we can be certain that if the `format`
 * matches the other format specific requirements are also met.
 *
 * Validation is done when resolving issuer metadata, or when calling `createIssuerMetadata`.
 */
export function extractKnownCredentialConfigurationSupportedFormats(
  credentialConfigurationsSupported: CredentialConfigurationsSupported
): CredentialConfigurationsSupportedWithFormats {
  return Object.fromEntries(
    Object.entries(credentialConfigurationsSupported).filter(
      (entry): entry is [string, CredentialConfigurationSupportedWithFormats] => {
        // Type guard to ensure that the returned entries have known formats
        const credentialConfiguration = zCredentialConfigurationSupportedWithFormats.safeParse(entry[1]) // Validate structure
        if (!credentialConfiguration.success) {
          return false
        }
        return allCredentialIssuerMetadataFormatIdentifiers.includes(
          credentialConfiguration.data.format as CredentialFormatIdentifier
        )
      }
    )
  )
}

/**
 * Get a known credential configuration supported by its id, it will throw an error if the configuration
 * is not found or if its found but the credential configuration is invalid.
 */
export function getKnownCredentialConfigurationSupportedById(
  issuerMetadata: IssuerMetadataResult,
  credentialConfigurationId: string
) {
  const configuration = issuerMetadata.credentialIssuer.credential_configurations_supported[credentialConfigurationId]

  if (!configuration) {
    throw new Oauth2Error(
      `Credential configuration with id '${credentialConfigurationId}' not found in credential configurations supported.`
    )
  }

  if (!issuerMetadata.knownCredentialConfigurations[credentialConfigurationId]) {
    parseWithErrorHandling(
      zCredentialConfigurationSupportedWithFormats,
      configuration,
      `Credential configuration with id '${credentialConfigurationId}' is not valid`
    )
  }

  return issuerMetadata.knownCredentialConfigurations[credentialConfigurationId]
}
