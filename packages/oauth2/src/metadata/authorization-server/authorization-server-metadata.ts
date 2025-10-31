import { type Fetch, joinUriParts, URL } from '@openid4vc/utils'
import { Oauth2Error } from '../../error/Oauth2Error'
import { fetchWellKnownMetadata } from '../fetch-well-known-metadata'
import { type AuthorizationServerMetadata, zAuthorizationServerMetadata } from './z-authorization-server-metadata'

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
  const parsedIssuerUrl = new URL(issuer)

  const openIdConfigurationWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownOpenIdConfigurationServerSuffix])
  const authorizationServerWellKnownMetadataUrl = joinUriParts(parsedIssuerUrl.origin, [
    wellKnownAuthorizationServerSuffix,
    parsedIssuerUrl.pathname,
  ])

  // NOTE: there is a difference in how to construct well-known OAuth2 and well-known openid
  // url. For OAuth you place `.well-known/oauth-authorization-server` between the origin and
  // the path. Historically we used the same method as OpenID (which a lot of servers seems to
  // host as well), and thus we use this as a last fallback if it's different for now (in case of subpath).
  const nonCompliantAuthorizationServerWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownAuthorizationServerSuffix])

  // First try oauth-authorization-server
  let authorizationServerResult = await fetchWellKnownMetadata(
    authorizationServerWellKnownMetadataUrl,
    zAuthorizationServerMetadata,
    fetch
  )

  if (
    !authorizationServerResult &&
    nonCompliantAuthorizationServerWellKnownMetadataUrl !== authorizationServerWellKnownMetadataUrl
  ) {
    authorizationServerResult = await fetchWellKnownMetadata(
      nonCompliantAuthorizationServerWellKnownMetadataUrl,
      zAuthorizationServerMetadata,
      fetch
    )
  }

  if (!authorizationServerResult) {
    authorizationServerResult = await fetchWellKnownMetadata(
      openIdConfigurationWellKnownMetadataUrl,
      zAuthorizationServerMetadata,
      fetch
    )
  }

  if (authorizationServerResult && authorizationServerResult.issuer !== issuer) {
    // issuer param MUST match
    throw new Oauth2Error(
      `The 'issuer' parameter '${authorizationServerResult.issuer}' in the well known authorization server metadata at '${authorizationServerWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
    )
  }

  return authorizationServerResult
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
      `Authorization server '${issuer}' not found in list of authorization servers. Available authorization servers are ${authorizationServersMetadata
        .map((as) => `'${as.issuer}'`)
        .join(', ')}`
    )
  }

  return authorizationServerMetadata
}
