import * as v from 'valibot'
import { Oid4vcError } from '../error/Oid4vcError'
import { Oid4vcValidationError } from '../error/Oid4vcValidationError'
import { getQueryParams } from '../utils/url'
import { type Fetch, createValibotFetcher } from '../utils/valibot-fetcher'
import {
  type CredentialOfferObject,
  preAuthorizedCodeGrantIdentifier,
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

    const { response, result } = await fetchWithValibot(vCredentialOfferObject, parsedQueryParams.credential_offer_uri)
    if (!response.ok || !result) {
      throw new Error(
        `Fetching well known metadata from '${parsedQueryParams.credential_offer_uri}' did not result in a succesfull response`
      )
    }

    credentialOfferParseResult = result
  } else if (parsedQueryParams.credential_offer) {
    let credentialOfferJson: Record<string, unknown>

    try {
      credentialOfferJson = JSON.parse(decodeURIComponent(parsedQueryParams.credential_offer))
    } catch (error) {
      throw new Oid4vcError(`Error parsing JSON from 'credential_offer' param in credential offer '${credentialOffer}'`)
    }

    credentialOfferParseResult = v.safeParse(vCredentialOfferObject, credentialOfferJson)
  } else {
    throw new Oid4vcError(`Credential offer did not contain either 'credential_offer' or 'credential_offer_uri' param.`)
  }

  if (credentialOfferParseResult.issues) {
    throw new Oid4vcValidationError(
      `Error parsing credential offer in draft 11, 13 or 14 format extracted from credential offer '${credentialOffer}'`,
      credentialOfferParseResult.issues
    )
  }

  return credentialOfferParseResult.output
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
