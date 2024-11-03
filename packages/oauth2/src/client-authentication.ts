import type { ContentType } from './common/content-type'

import type { FetchHeaders, HttpMethod } from '@animo-id/oid4vc-utils'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/v-authorization-server-metadata'

import { decodeUtf8String, encodeToBase64Url } from '@animo-id/oid4vc-utils'

/**
 * Options for client authentication
 */
export interface GetClientAuthenticationOptions {
  /**
   * Metadata of the authorization server
   */
  authorizationServerMetata: AuthorizationServerMetadata

  /**
   * URL to which the request will be made
   */
  url: string

  /**
   * http method that will be used
   */
  method: HttpMethod

  /**
   * Headers for the request. You can modify this object
   */
  headers: FetchHeaders

  contentType: ContentType

  /**
   * The body as a JSON object. If content type `x-www-form-urlencoded`
   * is used, it will be encoded after this call.
   *
   * You can modify this object
   */
  body: Record<string, unknown>
}

/**
 * Callback method to determine the client authentication for a request.
 */
export type ClientAuthenticationCallback = (options: GetClientAuthenticationOptions) => Promise<void> | void

export interface ClientAuthenticationClientSecretPostOptions {
  clientId: string
  clientSecret: string
}

/**
 * Client authentication using `client_secret_post` option
 */
export function clientAuthenticationClientSecretPost(
  options: ClientAuthenticationClientSecretPostOptions
): ClientAuthenticationCallback {
  return ({ body }) => {
    body.client_id = options.clientId
    body.client_secret = options.clientSecret
  }
}

export interface ClientAuthenticationClientSecretBasicOptions {
  clientId: string
  clientSecret: string
}

/**
 * Client authentication using `client_secret_basic` option
 */
export function clientAuthenticationClientSecretBasic(
  options: ClientAuthenticationClientSecretPostOptions
): ClientAuthenticationCallback {
  return ({ headers }) => {
    const authorization = encodeToBase64Url(decodeUtf8String(`${options.clientId}:${options.clientSecret}`))
    headers.set('Authorization', authorization)
  }
}

/**
 * No client authentication
 */
export function clientAuthenticationNone() {
  return () => {}
}
