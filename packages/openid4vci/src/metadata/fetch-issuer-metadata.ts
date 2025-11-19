import {
  type AuthorizationServerMetadata,
  type CallbackContext,
  fetchAuthorizationServerMetadata,
  Oauth2Error,
  zAuthorizationServerMetadata,
} from '@openid4vc/oauth2'

import { parseWithErrorHandling } from '@openid4vc/utils'
import type { Openid4vciDraftVersion } from '../version'
import {
  type CredentialIssuerMetadataSigned,
  extractKnownCredentialConfigurationSupportedFormats,
  fetchCredentialIssuerMetadata,
} from './credential-issuer/credential-issuer-metadata'
import type { CredentialConfigurationsSupportedWithFormats, CredentialIssuerMetadata } from './credential-issuer/z-credential-issuer-metadata'

export interface ResolveIssuerMetadataOptions {
  /**
   * Only fetch metadata for authorization servers that are part of this list. This can help if you know beforehand
   * which authorization servers will be used. The list is not validated to ensure all entries are also
   * in the issuer metadata.
   */
  restrictToAuthorizationServers?: string[]

  /**
   * Allow extracting authorization server metadata from the credential issuer metadata. This is added for backwards
   * compatibility with some implementations that did not host a separate authorization server metadata and will be removed
   * in a future version.
   *
   * @default true
   */
  allowAuthorizationMetadataFromCredentialIssuerMetadata?: boolean

  /**
   * Callbacks for fetching the credential issur metadata.
   * If no `verifyJwt` callback is provided, the request
   * will not include the `application/jwt` Accept header
   * for signed metadata.
   */
  callbacks: Partial<Pick<CallbackContext, 'fetch' | 'verifyJwt'>>

  /**
   * Only used for verifying signed issuer metadata. If not provided
   * current time will be used
   */
  now?: Date
}

export interface IssuerMetadataResult {
  originalDraftVersion: Openid4vciDraftVersion
  credentialIssuer: CredentialIssuerMetadata

  /**
   * Metadata about the signed credential issuer metadata,
   * if the issuer metadata was signed
   */
  signedCredentialIssuer?: CredentialIssuerMetadataSigned

  authorizationServers: AuthorizationServerMetadata[]

  knownCredentialConfigurations: CredentialConfigurationsSupportedWithFormats
}

export async function resolveIssuerMetadata(
  credentialIssuer: string,
  options?: ResolveIssuerMetadataOptions
): Promise<IssuerMetadataResult> {
  const allowAuthorizationMetadataFromCredentialIssuerMetadata =
    options?.allowAuthorizationMetadataFromCredentialIssuerMetadata ?? true

  const credentialIssuerMetadataWithDraftVersion = await fetchCredentialIssuerMetadata(credentialIssuer, {
    callbacks: options?.callbacks,
    now: options?.now,
  })
  if (!credentialIssuerMetadataWithDraftVersion) {
    throw new Oauth2Error(`Well known credential issuer metadata for issuer '${credentialIssuer}' not found.`)
  }

  const { credentialIssuerMetadata, originalDraftVersion, signed } = credentialIssuerMetadataWithDraftVersion

  // If no authoriation servers are defined, use the credential issuer as the authorization server
  const authorizationServers = credentialIssuerMetadata.authorization_servers ?? [credentialIssuer]

  const authoriationServersMetadata: AuthorizationServerMetadata[] = []
  for (const authorizationServer of authorizationServers) {
    if (
      options?.restrictToAuthorizationServers &&
      !options.restrictToAuthorizationServers.includes(authorizationServer)
    ) {
      continue
    }

    let authorizationServerMetadata = await fetchAuthorizationServerMetadata(
      authorizationServer,
      options?.callbacks.fetch
    )
    if (
      !authorizationServerMetadata &&
      authorizationServer === credentialIssuer &&
      allowAuthorizationMetadataFromCredentialIssuerMetadata
    ) {
      authorizationServerMetadata = parseWithErrorHandling(
        zAuthorizationServerMetadata,
        {
          token_endpoint: credentialIssuerMetadata.token_endpoint,
          issuer: credentialIssuer,
        },
        `Well known authorization server metadata for authorization server '${authorizationServer}' not found, and could also not extract required values from the credential issuer metadata as a fallback.`
      )
    }

    if (!authorizationServerMetadata) {
      throw new Oauth2Error(
        `Well known openid configuration or authorization server metadata for authorization server '${authorizationServer}' not found.`
      )
    }

    authoriationServersMetadata.push(authorizationServerMetadata)
  }

  // Collect all known credential configurations with formats
  const knownCredentialConfigurations = extractKnownCredentialConfigurationSupportedFormats(
    credentialIssuerMetadata.credential_configurations_supported
  )

  return {
    originalDraftVersion,
    credentialIssuer: credentialIssuerMetadata,
    signedCredentialIssuer: signed,

    authorizationServers: authoriationServersMetadata,
    knownCredentialConfigurations,
  }
}
