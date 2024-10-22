import { Oid4vcError } from '../../error/Oid4vcError'
import { joinUriParts } from '../../utils/path'
import type { Fetch } from '../../utils/valibot-fetcher'
import { fetchWellKnownMetadata } from '../fetch-metadata'
import { type CredentialIssuerMetadata, vCredentialIssuerMetadata } from './v-credential-issuer-metadata'

const wellKnownCredentialIssuerSuffix = '.well-known/openid-credential-issuer'

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchCredentialIssuerMetadata(
  credentialIssuer: string,
  fetch?: Fetch
): Promise<CredentialIssuerMetadata | null> {
  const wellKnownMetadataUrl = joinUriParts(credentialIssuer, [wellKnownCredentialIssuerSuffix])
  const result = await fetchWellKnownMetadata(wellKnownMetadataUrl, vCredentialIssuerMetadata, fetch)

  // credential issuer param MUST match
  if (result && result.credential_issuer !== credentialIssuer) {
    throw new Oid4vcError(
      `The 'credential_issuer' parameter '${result.credential_issuer}' in the well known credential issuer metadata at '${wellKnownMetadataUrl}' does not match the provided credential issuer '${credentialIssuer}'.`
    )
  }

  return result
}
