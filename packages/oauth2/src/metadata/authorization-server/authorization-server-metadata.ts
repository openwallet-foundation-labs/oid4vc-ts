import { type Fetch, joinUriParts } from '@openid4vc/utils'
import { Oauth2Error } from '../../error/Oauth2Error'
import { fetchWellKnownMetadata } from '../fetch-well-known-metadata'
import { type AuthorizationServerMetadata, vAuthorizationServerMetadata } from './v-authorization-server-metadata'

const wellKnownAuthorizationServerSuffix = '.well-known/oauth-authorization-server'
const wellKnownOpenIdConfigurationServerSuffix = '.well-known/openid-configuration'

/**
 * fetch authorization server metadata. It first tries to fetch the oauth-authorization-server metadata. If that returns
 *  a 404, the openid-configuration metadata will be fetched.
 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
  fetch?: Fetch
): Promise<AuthorizationServerMetadata | null> {
  const openIdConfigurationWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownOpenIdConfigurationServerSuffix])
  const authorizationServerWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownAuthorizationServerSuffix])

  // First try oauth-authorization-server
  const authorizationServerResult = await fetchWellKnownMetadata(
    authorizationServerWellKnownMetadataUrl,
    vAuthorizationServerMetadata,
    fetch
  )

  if (authorizationServerResult) {
    if (authorizationServerResult.issuer !== issuer) {
      // issuer param MUST match
      throw new Oauth2Error(
        `The 'issuer' parameter '${authorizationServerResult.issuer}' in the well known authorization server metadata at '${authorizationServerWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
      )
    }

    return authorizationServerResult
  }

  const openIdConfigurationResult = await fetchWellKnownMetadata(
    openIdConfigurationWellKnownMetadataUrl,
    vAuthorizationServerMetadata,
    fetch
  )

  // issuer param MUST match
  if (openIdConfigurationResult) {
    if (openIdConfigurationResult.issuer !== issuer) {
      throw new Oauth2Error(
        `The 'issuer' parameter '${openIdConfigurationResult.issuer}' in the well openid configuration metadata at '${openIdConfigurationWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
      )
    }
    return openIdConfigurationResult
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
