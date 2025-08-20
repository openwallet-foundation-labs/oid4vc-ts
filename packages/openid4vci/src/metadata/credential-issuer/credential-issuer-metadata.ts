import { Oauth2Error, fetchWellKnownMetadata } from '@openid4vc/oauth2'
import { type Fetch, joinUriParts } from '@openid4vc/utils'
import type { CredentialFormatIdentifier } from '../../formats/credential'
import type { Openid4vciDraftVersion } from '../../version'
import {
  type CredentialConfigurationSupported,
  type CredentialConfigurationSupportedWithFormats,
  type CredentialConfigurationsSupported,
  type CredentialConfigurationsSupportedWithFormats,
  type CredentialIssuerMetadata,
  allCredentialIssuerMetadataFormatIdentifiers,
  zCredentialIssuerMetadataWithDraftVersion,
} from './z-credential-issuer-metadata'

const wellKnownCredentialIssuerSuffix = '.well-known/openid-credential-issuer'

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchCredentialIssuerMetadata(
  credentialIssuer: string,
  fetch?: Fetch
): Promise<{
  credentialIssuerMetadata: CredentialIssuerMetadata
  originalDraftVersion: Openid4vciDraftVersion
} | null> {
  const wellKnownMetadataUrl = joinUriParts(credentialIssuer, [wellKnownCredentialIssuerSuffix])
  const result = await fetchWellKnownMetadata(wellKnownMetadataUrl, zCredentialIssuerMetadataWithDraftVersion, fetch)

  // credential issuer param MUST match
  if (result && result.credentialIssuerMetadata.credential_issuer !== credentialIssuer) {
    throw new Oauth2Error(
      `The 'credential_issuer' parameter '${result.credentialIssuerMetadata.credential_issuer}' in the well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return result
}

/**
 * Extract credential configuration supported entries where the `format` is known to this
 * library. Should be ran only after verifying the credential issuer metadata structure, so
 * we can be certain that if the `format` matches the other format specific requirements are also met.
 *
 * Validation is done when resolving issuer metadata, or when calling `createIssuerMetadata`.
 */
export function extractKnownCredentialConfigurationSupportedFormats(
  credentialConfigurationsSupported: CredentialConfigurationsSupported
): CredentialConfigurationsSupportedWithFormats {
  return Object.fromEntries(
    Object.entries(credentialConfigurationsSupported).filter(
      (entry): entry is [string, CredentialConfigurationSupportedWithFormats] =>
        allCredentialIssuerMetadataFormatIdentifiers.includes(entry[1].format as CredentialFormatIdentifier)
    )
  )
}

export function getCredentialConfigurationSupportedById<
  Configurations extends CredentialConfigurationsSupported | CredentialConfigurationsSupportedWithFormats,
>(credentialConfigurations: Configurations, credentialConfigurationId: string) {
  const configuration = credentialConfigurations[credentialConfigurationId]

  if (!configuration) {
    throw new Oauth2Error(
      `Credential configuration with id '${credentialConfigurationId}' not found in credential configurations supported.`
    )
  }

  return configuration as Configurations extends CredentialConfigurationsSupportedWithFormats
    ? CredentialConfigurationSupportedWithFormats
    : CredentialConfigurationSupported
}
