import { Oid4vcError } from '../../error/Oid4vcError'
import type { Fetch } from '../../globals'
import { joinUriParts } from '../../utils/path'
import type { Oid4vciDraftVersion } from '../../versions/draft-version'
import { fetchWellKnownMetadata } from '../fetch-metadata'
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
    throw new Oid4vcError(
      `The 'credential_issuer' parameter '${result.credentialIssuerMetadata.credential_issuer}' in the well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return result
}
