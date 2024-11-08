import * as v from 'valibot'

import {
  type AuthorizationCodeGrantIdentifier,
  type CallbackContext,
  InvalidFetchResponseError,
  Oauth2Error,
  type PreAuthorizedCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  getAuthorizationServerMetadataFromList,
  preAuthorizedCodeGrantIdentifier,
} from '@animo-id/oauth2'
import {
  ContentType,
  type Fetch,
  URL,
  URLSearchParams,
  ValidationError,
  createValibotFetcher,
  encodeToBase64Url,
  getQueryParams,
  objectToQueryParams,
  parseWithErrorHandling,
} from '@animo-id/oauth2-utils'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Oid4vciDraftVersion } from '../version'
import {
  type CredenialOfferAuthorizationCodeGrant,
  type CredentialOfferGrants,
  type CredentialOfferObject,
  type CredentialOfferPreAuthorizedCodeGrant,
  vCredentialOfferObject,
} from './v-credential-offer'

export interface ResolveCredentialOfferOptions {
  /**
   * Custom fetch implementation to use
   */
  fetch?: Fetch
}

/**
 * Resolve a credential offer, optionally fetching it if the credential_offer_uri is provided.
 */
export async function resolveCredentialOffer(
  credentialOffer: string,
  options?: ResolveCredentialOfferOptions
): Promise<CredentialOfferObject> {
  const parsedQueryParams = getQueryParams(credentialOffer)

  let credentialOfferParseResult: v.SafeParseResult<typeof vCredentialOfferObject>

  if (parsedQueryParams.credential_offer_uri) {
    const fetchWithValibot = createValibotFetcher(options?.fetch)

    const { response, result } = await fetchWithValibot(
      vCredentialOfferObject,
      ContentType.Json,
      parsedQueryParams.credential_offer_uri
    )
    if (!response.ok || !result) {
      throw new InvalidFetchResponseError(
        `Fetching credential offer from '${parsedQueryParams.credential_offer_uri}' resulted in an unsuccesfull response with status '${response.status}'`,
        await response.clone().text(),
        response
      )
    }

    credentialOfferParseResult = result
  } else if (parsedQueryParams.credential_offer) {
    let credentialOfferJson: Record<string, unknown>

    try {
      credentialOfferJson = JSON.parse(decodeURIComponent(parsedQueryParams.credential_offer))
    } catch (error) {
      throw new Oauth2Error(`Error parsing JSON from 'credential_offer' param in credential offer '${credentialOffer}'`)
    }

    credentialOfferParseResult = v.safeParse(vCredentialOfferObject, credentialOfferJson)
  } else {
    throw new Oauth2Error(`Credential offer did not contain either 'credential_offer' or 'credential_offer_uri' param.`)
  }

  if (credentialOfferParseResult.issues) {
    throw new ValidationError(
      `Error parsing credential offer in draft 11, 13 or 14 format extracted from credential offer '${credentialOffer}'`,
      credentialOfferParseResult.issues
    )
  }

  return credentialOfferParseResult.output
}

export interface CreateCredentialOfferOptions {
  issuerMetadata: IssuerMetadataResult

  /**
   * The credential configuration ids to be offered
   */
  credentialConfigurationIds: string[]

  /**
   * Grants to include in the credential offer
   */
  grants: {
    [preAuthorizedCodeGrantIdentifier]?: Partial<CredentialOfferPreAuthorizedCodeGrant>
    [authorizationCodeGrantIdentifier]?: CredenialOfferAuthorizationCodeGrant

    [key: string]: unknown
  }

  /**
   * Additional payload to include in the body of the credential offer. Will be applied
   * after the other fields, allowing to override common properties, so be cautious.
   */
  additionalPayload?: Record<string, unknown>

  /**
   * If provided the encoded credential offer will use the `credential_offer_uri` parameter
   * instaed of directly adding the `credential_offer`. Requires hosting of the `credential_offer_uri`
   */
  credentialOfferUri?: string

  /**
   * The scheme to use for the credential offer.
   *
   * @default `openid-credential-offer://`
   */
  credentialOfferScheme?: string

  /**
   * Callbacks used to create credential offer
   */
  callbacks: Pick<CallbackContext, 'generateRandom'>
}

interface DetermineAuthorizationServerForGrant {
  issuerMetadata: IssuerMetadataResult
  grantAuthorizationServer?: string
}

export function determineAuthorizationServerForCredentialOffer(options: DetermineAuthorizationServerForGrant) {
  const authorizationServers = options.issuerMetadata.credentialIssuer.authorization_servers

  let authorizationServer: string
  if (options.grantAuthorizationServer) {
    authorizationServer = options.grantAuthorizationServer

    if (!authorizationServers) {
      throw new Oauth2Error(
        `Credential offer grant contains 'authorization_server' with value '${options.grantAuthorizationServer}' but credential issuer metadata does not have an 'authorization_servers' property to match the value against.`
      )
    }
    if (!authorizationServers.includes(authorizationServer)) {
      throw new Oauth2Error(
        `Credential offer grant contains 'authorization_server' with value '${options.grantAuthorizationServer}' but credential issuer metadata does not include this authorization server. Available 'authorization_server' values are ${authorizationServers.join(', ')}.`
      )
    }
  } else if (!authorizationServers) {
    authorizationServer = options.issuerMetadata.credentialIssuer.credential_issuer
  } else {
    if (authorizationServers.length === 0) {
      throw new Oauth2Error(`Credential issuer metadata has 'authorization_servers' value with length of 0`)
    }
    if (authorizationServers.length > 1) {
      throw new Oauth2Error(
        `Credential issuer metadata has 'authorization_server' with multiple entries, but the credential offer grant did not specify which authorization server to use.`
      )
    }

    authorizationServer = authorizationServers[0]
  }

  return authorizationServer
}

export async function createCredentialOffer(options: CreateCredentialOfferOptions) {
  const {
    [preAuthorizedCodeGrantIdentifier]: preAuthorizedCodeGrant,
    [authorizationCodeGrantIdentifier]: authorizationCodeGrant,
    ...restGrants
  } = options.grants
  const grants: CredentialOfferGrants = { ...restGrants }

  if (authorizationCodeGrant) {
    determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: authorizationCodeGrant.authorization_server,
    })

    grants[authorizationCodeGrantIdentifier] = authorizationCodeGrant
  }

  if (preAuthorizedCodeGrant) {
    determineAuthorizationServerForCredentialOffer({
      issuerMetadata: options.issuerMetadata,
      grantAuthorizationServer: preAuthorizedCodeGrant.authorization_server,
    })

    grants[preAuthorizedCodeGrantIdentifier] = {
      ...preAuthorizedCodeGrant,
      'pre-authorized_code':
        preAuthorizedCodeGrant['pre-authorized_code'] ?? encodeToBase64Url(await options.callbacks.generateRandom(32)),
    }

    // Draft 11 support
    const txCode = grants[preAuthorizedCodeGrantIdentifier].tx_code
    if (txCode && options.issuerMetadata.originalDraftVersion === Oid4vciDraftVersion.Draft11) {
      grants[preAuthorizedCodeGrantIdentifier].user_pin_required = txCode !== undefined
    }
  }

  const idsNotInMetadata = options.credentialConfigurationIds.filter(
    (id) => options.issuerMetadata.credentialIssuer.credential_configurations_supported[id] === undefined
  )
  if (idsNotInMetadata.length > 0) {
    throw new Oauth2Error(
      `Credential configuration ids ${idsNotInMetadata} not found in the credential issuer metadata 'credential_configurations_supported'. Available ids are ${Object.keys(options.issuerMetadata.credentialIssuer.credential_configurations_supported).join(', ')}.`
    )
  }

  const credentialOfferScheme = options.credentialOfferScheme ?? 'openid-credential-offer://'
  const credentialOfferObject = parseWithErrorHandling(vCredentialOfferObject, {
    credential_issuer: options.issuerMetadata.credentialIssuer.credential_issuer,
    credential_configuration_ids: options.credentialConfigurationIds,
    grants,
    ...options.additionalPayload,
  } satisfies CredentialOfferObject)

  // Draft 11 support
  if (options.issuerMetadata.originalDraftVersion === Oid4vciDraftVersion.Draft11) {
    credentialOfferObject.credentials = credentialOfferObject.credential_configuration_ids
  }

  const url = new URL(credentialOfferScheme)
  url.search = `?${new URLSearchParams([
    ...url.searchParams.entries(),
    ...objectToQueryParams({
      credential_offer_uri: options.credentialOfferUri,
      // Only add credential_offer is uri is undefined
      credential_offer: options.credentialOfferUri ? undefined : credentialOfferObject,
    }).entries(),
  ]).toString()}`

  return {
    credentialOffer: url.toString(),
    credentialOfferObject,
  }
}

/**
 * Extract the authorization servers from the grants in a credential offer. If no authorization servers
 * are present, null is returned.
 */
export function extractAuthorizationServersFromCredentialOfferObject(
  credentialOfferObject: CredentialOfferObject
): string[] | null {
  const authorizationServers: string[] = []

  if (credentialOfferObject.grants?.[preAuthorizedCodeGrantIdentifier]?.authorization_server) {
    authorizationServers.push(credentialOfferObject.grants?.[preAuthorizedCodeGrantIdentifier]?.authorization_server)
  }

  if (credentialOfferObject.grants?.authorization_code?.authorization_server) {
    authorizationServers.push(credentialOfferObject.grants?.authorization_code?.authorization_server)
  }

  return authorizationServers.length > 0 ? authorizationServers : null
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
  throw new Oauth2Error(
    `Unable to determine authorization server. Multiple authorization servers available and credential offer does not specify which 'authorization_server' to use for the '${options.grantType}' grant type.`
  )
}
