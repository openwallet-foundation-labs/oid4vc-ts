import { Oauth2Error, fetchWellKnownMetadata } from '@animo-id/oauth2'
import { type Fetch, joinUriParts } from '@animo-id/oid4vc-utils'
import type { Oid4vciDraftVersion } from '../../version'
import {
  type CredentialIssuerMetadata,
  vCredentialIssuerMetadataWithDraftVersion,
} from './v-credential-issuer-metadata'

const wellKnownCredentialIssuerSuffix = '.well-known/openid-credential-issuer'

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchCredentialIssuerMetadata(
  credentialIssuer: string,
  fetch?: Fetch
): Promise<{ credentialIssuerMetadata: CredentialIssuerMetadata; originalDraftVersion: Oid4vciDraftVersion } | null> {
  const wellKnownMetadataUrl = joinUriParts(credentialIssuer, [wellKnownCredentialIssuerSuffix])
  const result = await fetchWellKnownMetadata(wellKnownMetadataUrl, vCredentialIssuerMetadataWithDraftVersion, fetch)

  // credential issuer param MUST match
  if (result && result.credentialIssuerMetadata.credential_issuer !== credentialIssuer) {
    throw new Oauth2Error(
      `The 'credential_issuer' parameter '${result.credentialIssuerMetadata.credential_issuer}' in the well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return result
}
