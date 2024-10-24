import type {
  AuthorizationCodeGrantIdentifier,
  CredentialOfferObject,
  PreAuthorizedCodeGrantIdentifier,
} from '../../credential-offer/v-credential-offer'
import { Oid4vcError } from '../../error/Oid4vcError'
import type { Fetch } from '../../globals'
import { joinUriParts } from '../../utils/path'
import type { IssuerMetadataResult } from '../fetch-issuer-metadata'
import { fetchWellKnownMetadata } from '../fetch-metadata'
import { type AuthorizationServerMetadata, vAuthorizationServerMetadata } from './v-authorization-server-metadata'

const wellKnownAuthorizationServerSuffix = '.well-known/oauth-authorization-server'
const wellKnownOpenIdConfigurationServerSuffix = '.well-known/openid-configuration'

/**
 * @inheritdoc {@link fetchWellKnownMetadata}
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
      throw new Oid4vcError(
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
      throw new Oid4vcError(
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
    throw new Oid4vcError(
      `Authorization server '${issuer}' not found in list of authorization servers. Availalbe authorization servers are ${authorizationServersMetadata
        .map((as) => `'${as.issuer}'`)
        .join(', ')}`
    )
  }

  return authorizationServerMetadata
}

export interface DetermineAuthorizationForOfferOptions {
  grantType: PreAuthorizedCodeGrantIdentifier | AuthorizationCodeGrantIdentifier
  credentialOffer: CredentialOfferObject
  issuerMetadata: IssuerMetadataResult
}

export function determineAuthorizationServerForOffer(options: DetermineAuthorizationForOfferOptions) {
  // Try infer authorization server based on credential offer
  const authorizationServer = options.credentialOffer.grants?.[options.grantType]?.authorization_server
  if (authorizationServer) {
    return getAuthorizationServerMetadataFromList(options.issuerMetadata.authorizationServers, authorizationServer)
  }

  // Otherwise if there's only one we can use that
  if (options.issuerMetadata.authorizationServers.length === 1) {
    return options.issuerMetadata.authorizationServers[0]
  }

  // We can't safely determine the authorization server
  throw new Oid4vcError(
    `Unable to determine authorization server. Multiple authorization servers available and credential offer does not specify which 'authorization_server' to use for the '${options.grantType}' grant type.`
  )
}
