import { type Fetch, joinUriParts } from '@openid4vc/utils'
import { Oauth2Error } from '../../error/Oauth2Error'
import { fetchWellKnownMetadata } from '../fetch-well-known-metadata'
import { type AuthorizationServerMetadata, vAuthorizationServerMetadata } from './v-authorization-server-metadata'

const wellKnownAuthorizationServerSuffix = '.well-known/oauth-authorization-server'
const wellKnownOpenIdConfigurationServerSuffix = '.well-known/openid-configuration'

/**
 * fetch authorization server metadata. It first tries to fetch the openid configuration. If that reutrns
 *  a 404, the oauth authorization server metadata will be tries.
 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
  fetch?: Fetch
): Promise<AuthorizationServerMetadata | null> {
  // First try openid configuration
  const openIdConfigurationWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownOpenIdConfigurationServerSuffix])
  const openIdConfigurationResult = await fetchWellKnownMetadata(
    openIdConfigurationWellKnownMetadataUrl,
    vAuthorizationServerMetadata,
    fetch
  )

  if (openIdConfigurationResult) {
    if (openIdConfigurationResult.issuer !== issuer) {
      // issuer param MUST match
      throw new Oauth2Error(
        `The 'issuer' parameter '${openIdConfigurationResult.issuer}' in the well known openid configuration at '${openIdConfigurationWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
      )
    }

    return openIdConfigurationResult
  }

  const authorizationServerWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownAuthorizationServerSuffix])
  const authorizationServerResult = await fetchWellKnownMetadata(
    authorizationServerWellKnownMetadataUrl,
    vAuthorizationServerMetadata,
    fetch
  )

  // issuer param MUST match
  if (authorizationServerResult) {
    if (authorizationServerResult.issuer !== issuer) {
      throw new Oauth2Error(
        `The 'issuer' parameter '${authorizationServerResult.issuer}' in the well known authorization server metadata at '${authorizationServerWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
      )
    }
    return authorizationServerResult
  }

  return null
}

export function getAuthorizationServerMetadataFromList(
  authorizationServersMetadata: AuthorizationServerMetadata[],
  issuer: string
) {
  const authorizationServerMetadata = authorizationServersMetadata.find(
    (authorizationServerMetadata) => authorizationServerMetadata.issuer === issuer
  )

  if (!authorizationServerMetadata) {
    throw new Oauth2Error(
      `Authorization server '${issuer}' not found in list of authorization servers. Availalbe authorization servers are ${authorizationServersMetadata
        .map((as) => `'${as.issuer}'`)
        .join(', ')}`
    )
  }

  return authorizationServerMetadata
}
