import type { ContentType, FetchHeaders, HttpMethod } from '@animo-id/oauth2-utils'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/v-authorization-server-metadata'

import { decodeUtf8String, encodeToBase64Url } from '@animo-id/oauth2-utils'
import { Oauth2Error } from './error/Oauth2Error'

// These two are well-supported and easy to implement
export enum SupportedClientAuthenticationMethod {
  ClientSecretBasic = 'client_secret_basic',
  ClientSecretPost = 'client_secret_post',
}

type ClientAuthenticationEndpointType = 'endpoint' | 'introspection'

/**
 * Determine the supported client authentication method based on authorization
 * server metadata
 */
export function getSupportedClientAuthenticationMethod(
  authorizationServer: AuthorizationServerMetadata,
  endpointType: ClientAuthenticationEndpointType
): SupportedClientAuthenticationMethod {
  if (endpointType === 'introspection' && authorizationServer.introspection_endpoint_auth_methods_supported) {
    const supportedMethod = authorizationServer.introspection_endpoint_auth_methods_supported.find(
      (m): m is SupportedClientAuthenticationMethod =>
        Object.values(SupportedClientAuthenticationMethod).includes(m as SupportedClientAuthenticationMethod)
    )

    if (!supportedMethod) {
      throw new Oauth2Error(
        `Authorization server metadata for issuer '${
          authorizationServer.issuer
        }' has 'introspection_endpoint_auth_methods_supported' metadata, but does not contain a supported value. Supported values are '${Object.values(
          SupportedClientAuthenticationMethod
        ).join(
          ', '
        )}', found values are '${authorizationServer.introspection_endpoint_auth_methods_supported.join(', ')}'`
      )
    }

    return supportedMethod
  }

  // We allow the introspection endpoint to fallback on the token endpoint metadata if the introspection
  // metadata is not defined
  if (authorizationServer.token_endpoint_auth_methods_supported) {
    const supportedMethod = authorizationServer.token_endpoint_auth_methods_supported.find(
      (m): m is SupportedClientAuthenticationMethod =>
        Object.values(SupportedClientAuthenticationMethod).includes(m as SupportedClientAuthenticationMethod)
    )

    if (!supportedMethod) {
      throw new Oauth2Error(
        `Authorization server metadata for issuer '${
          authorizationServer.issuer
        }' has 'token_endpoint_auth_methods_supported' metadata, but does not contain a supported value. Supported values are '${Object.values(
          SupportedClientAuthenticationMethod
        ).join(', ')}', found values are '${authorizationServer.token_endpoint_auth_methods_supported.join(', ')}'`
      )
    }

    return supportedMethod
  }

  // If omitted from metadata, the default is "client_secret_basic" according to rfc8414
  return SupportedClientAuthenticationMethod.ClientSecretBasic
}

export interface ClientAuthenticationDynamicOptions {
  clientId: string
  clientSecret: string
}

/**
 * Dynamicaly get the client authentication method based on endpoint type and authorization server.
 * Only `client_secret_post` and `client_secret_basic` supported.
 */
export function clientAuthenticationDynamic(options: ClientAuthenticationDynamicOptions): ClientAuthenticationCallback {
  return (callbackOptions) => {
    const { url, authorizationServerMetata } = callbackOptions
    const endpointType: ClientAuthenticationEndpointType =
      url === authorizationServerMetata.introspection_endpoint ? 'introspection' : 'endpoint'
    const method = getSupportedClientAuthenticationMethod(authorizationServerMetata, endpointType)

    if (method === SupportedClientAuthenticationMethod.ClientSecretBasic) {
      return clientAuthenticationClientSecretBasic(options)(callbackOptions)
    }

    if (method === SupportedClientAuthenticationMethod.ClientSecretPost) {
      return clientAuthenticationClientSecretPost(options)(callbackOptions)
    }

    throw new Oauth2Error(
      `Unsupported client auth method ${method}. Supported values are ${Object.values(
        SupportedClientAuthenticationMethod
      ).join(', ')}`
    )
  }
}

/**
 * Options for client authentication
 */
export interface ClientAuthenticationCallbackOptions {
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
export type ClientAuthenticationCallback = (options: ClientAuthenticationCallbackOptions) => Promise<void> | void

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
