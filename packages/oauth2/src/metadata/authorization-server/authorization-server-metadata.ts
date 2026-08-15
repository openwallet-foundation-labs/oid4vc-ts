import { type Fetch, joinUriParts, OpenId4VcBaseError, parseWithErrorHandling, URL } from '@openid4vc/utils'
import type { CallbackContext } from '../../callbacks'
import { Oauth2Error } from '../../error/Oauth2Error'
import { fetchWellKnownMetadata } from '../fetch-well-known-metadata'
import { type AuthorizationServerMetadata, zAuthorizationServerMetadata } from './z-authorization-server-metadata'

const wellKnownAuthorizationServerSuffix = '.well-known/oauth-authorization-server'
const wellKnownOpenIdConfigurationServerSuffix = '.well-known/openid-configuration'

/**
 * fetch authorization server metadata. It first tries to fetch the oauth-authorization-server metadata. If that returns
 *  a 404, the openid-configuration metadata will be fetched.
 *
 * If a `getAuthorizationServerMetadata` callback is provided and returns metadata for the `issuer`,
 * that metadata is returned and no requests are performed. The `issuer` value of the returned
 * metadata MUST still match the requested `issuer`.
 */
export async function fetchAuthorizationServerMetadata(
  issuer: string,
  callbacksOrFetch?: Fetch | Pick<CallbackContext, 'fetch' | 'getAuthorizationServerMetadata'>
): Promise<AuthorizationServerMetadata | null> {
  const callbacks = typeof callbacksOrFetch === 'function' ? { fetch: callbacksOrFetch } : callbacksOrFetch
  const providedMetadata = await callbacks?.getAuthorizationServerMetadata?.(issuer)

  // `null` means the callback determined the metadata does not exist, so we don't fetch it again.
  if (providedMetadata === null) return null

  if (providedMetadata) {
    // Validated the same way as metadata retrieved from the well known endpoints
    const parsedMetadata = parseWithErrorHandling(
      zAuthorizationServerMetadata,
      providedMetadata,
      `Validation of authorization server metadata provided by the 'getAuthorizationServerMetadata' callback for issuer '${issuer}' failed`
    )

    if (parsedMetadata.issuer !== issuer) {
      // issuer param MUST match, also for metadata that was not fetched
      throw new Oauth2Error(
        `The 'issuer' parameter '${parsedMetadata.issuer}' in the authorization server metadata provided by the 'getAuthorizationServerMetadata' callback does not match the provided issuer '${issuer}'.`
      )
    }

    return parsedMetadata
  }

  const fetch = callbacks?.fetch
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

  let firstError: Error | null = null

  // First try oauth-authorization-server
  let authorizationServerResult = await fetchWellKnownMetadata(
    authorizationServerWellKnownMetadataUrl,
    zAuthorizationServerMetadata,
    {
      fetch,
    }
  ).catch((error) => {
    if (error instanceof OpenId4VcBaseError) throw error

    // An exception occurs if a CORS-policy blocks the request, i.e. because the URL is invalid due to the legacy path being used
    // The legacy path should still be tried therefore we store the first error to rethrow it later if needed
    firstError = error
  })

  if (
    !authorizationServerResult &&
    nonCompliantAuthorizationServerWellKnownMetadataUrl !== authorizationServerWellKnownMetadataUrl
  ) {
    authorizationServerResult = await fetchWellKnownMetadata(
      nonCompliantAuthorizationServerWellKnownMetadataUrl,
      zAuthorizationServerMetadata,
      {
        fetch,
      }
    ).catch((error) => {
      // Similar to above, if there was a library error, we throw it.
      // However in other cases we swallow it, we only keep the first error
      if (error instanceof OpenId4VcBaseError) throw error
    })
  }

  if (!authorizationServerResult) {
    authorizationServerResult = await fetchWellKnownMetadata(
      openIdConfigurationWellKnownMetadataUrl,
      zAuthorizationServerMetadata,
      {
        fetch,
      }
    ).catch((error) => {
      throw firstError ?? error
    })
  }

  if (!authorizationServerResult && firstError) {
    throw firstError
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
