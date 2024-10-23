import { Oid4vcError } from '../../error/Oid4vcError'
import type { Fetch } from '../../globals'
import { joinUriParts } from '../../utils/path'
import { fetchWellKnownMetadata } from '../fetch-metadata'
import { type AuthorizationServerMetadata, vAuthorizationServerMetadata } from './v-authorization-server-metadata'

const wellKnownAuthorizationServerSuffix = '.well-known/oauth-authorization-server'

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
  fetch?: Fetch
): Promise<AuthorizationServerMetadata | null> {
  const wellKnownMetadataUrl = joinUriParts(issuer, [wellKnownAuthorizationServerSuffix])
  const result = await fetchWellKnownMetadata(wellKnownMetadataUrl, vAuthorizationServerMetadata, fetch)

  // issuer param MUST match
  if (result && result.issuer !== issuer) {
    throw new Oid4vcError(
      `The 'issuer' parameter '${result.issuer}' in the well known authorization server metadata at '${wellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
    )
  }

  return result
}

export function getAuthorizationServerMetadataFromList(
  authorizationServersMetadata: AuthorizationServerMetadata[],
  issuer: string
) {
  const authorizationServerMetadata = authorizationServersMetadata.find(
    (authorizationServerMetadata) => authorizationServerMetadata.issuer === issuer
  )

  if (!authorizationServerMetadata) {
    throw new Oid4vcError(
      `Authorization server '${issuer}' not found in list of authorization servers. Availalbe authorization servers are ${authorizationServersMetadata.map((as) => `'${as.issuer}'`).join(', ')}`
    )
  }

  return authorizationServerMetadata
}
