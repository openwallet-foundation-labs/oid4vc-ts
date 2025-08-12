import { type Fetch, URL, joinUriParts } from '@openid4vc/utils'
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
  const openIdConfigurationWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownOpenIdConfigurationServerSuffix])

  const parsedIssuerUrl = new URL(issuer)

  const authorizationServerWellKnownMetadataUrl = joinUriParts(parsedIssuerUrl.origin, [
    wellKnownAuthorizationServerSuffix,
    parsedIssuerUrl.pathname,
  ])

  // First try oauth-authorization-server
  const authorizationServerResult = await fetchWellKnownMetadata(
    authorizationServerWellKnownMetadataUrl,
    zAuthorizationServerMetadata,
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

  // NOTE: there is a difference in how to construct well-known OAuth2 and well-known openid
  // url. For OAuth you place `.well-known/oauth-authorization-server` between the origin and
  // the path. Historically we used the same method as OpenID (which a lot of servers seems to
  // host as well), and thus we use this as a last fallback if it's different for now (in case of subpath).
  const nonCompliantAuthorizationServerWellKnownMetadataUrl = joinUriParts(issuer, [wellKnownAuthorizationServerSuffix])

  const alternativeAuthorizationServerResult =
    nonCompliantAuthorizationServerWellKnownMetadataUrl !== authorizationServerWellKnownMetadataUrl
      ? await fetchWellKnownMetadata(
          nonCompliantAuthorizationServerWellKnownMetadataUrl,
          zAuthorizationServerMetadata,
          fetch
        )
      : undefined

  if (alternativeAuthorizationServerResult) {
    if (alternativeAuthorizationServerResult.issuer !== issuer) {
      // issuer param MUST match
      throw new Oauth2Error(
        `The 'issuer' parameter '${alternativeAuthorizationServerResult.issuer}' in the well known authorization server metadata at '${nonCompliantAuthorizationServerWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
      )
    }

    return alternativeAuthorizationServerResult
  }

  const openIdConfigurationResult = await fetchWellKnownMetadata(
    openIdConfigurationWellKnownMetadataUrl,
    zAuthorizationServerMetadata,
    fetch
  )

  // issuer param MUST match
  if (openIdConfigurationResult) {
    if (openIdConfigurationResult.issuer !== issuer) {
      throw new Oauth2Error(
        `The 'issuer' parameter '${openIdConfigurationResult.issuer}' in the well known openid configuration metadata at '${openIdConfigurationWellKnownMetadataUrl}' does not match the provided issuer '${issuer}'.`
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
      `Authorization server '${issuer}' not found in list of authorization servers. Available authorization servers are ${authorizationServersMetadata
        .map((as) => `'${as.issuer}'`)
        .join(', ')}`
    )
  }

  return authorizationServerMetadata
}
