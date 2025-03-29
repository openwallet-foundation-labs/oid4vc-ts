import type { ContentType, FetchHeaders, HttpMethod } from '@openid4vc/utils'
import type { AuthorizationServerMetadata } from './metadata/authorization-server/z-authorization-server-metadata'

import { decodeUtf8String, encodeToBase64Url } from '@openid4vc/utils'
import type { CallbackContext } from './callbacks'
import { createClientAttestationPopJwt } from './client-attestation/client-attestation-pop'
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from './client-attestation/z-client-attestation'
import { Oauth2Error } from './error/Oauth2Error'
import { preAuthorizedCodeGrantIdentifier } from './z-grant-type'

export enum SupportedClientAuthenticationMethod {
  ClientSecretBasic = 'client_secret_basic',
  ClientSecretPost = 'client_secret_post',
  ClientAttestationJwt = 'attest_jwt_client_auth',
  None = 'none',
}

type ClientAuthenticationEndpointType = 'endpoint' | 'token' | 'introspection'

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
 * Only `client_secret_post`, `client_secret_basic`, and `none` supported.
 *
 * It also supports anonymous access to the token endpoint for pre-authorized code flow
 * if the authorization server has enabled `pre-authorized_grant_anonymous_access_supported`
 */
export function clientAuthenticationDynamic(options: ClientAuthenticationDynamicOptions): ClientAuthenticationCallback {
  return (callbackOptions) => {
    const { url, authorizationServerMetadata, body } = callbackOptions
    const endpointType: ClientAuthenticationEndpointType =
      url === authorizationServerMetadata.introspection_endpoint
        ? 'introspection'
        : url === authorizationServerMetadata.token_endpoint
          ? 'token'
          : 'endpoint'
    const method = getSupportedClientAuthenticationMethod(authorizationServerMetadata, endpointType)

    // Special case for pre-auth flow where we can use anonymous client
    if (
      endpointType === 'token' &&
      body.grant_type === preAuthorizedCodeGrantIdentifier &&
      authorizationServerMetadata['pre-authorized_grant_anonymous_access_supported']
    ) {
      return clientAuthenticationAnonymous()(callbackOptions)
    }

    if (method === SupportedClientAuthenticationMethod.ClientSecretBasic) {
      return clientAuthenticationClientSecretBasic(options)(callbackOptions)
    }

    if (method === SupportedClientAuthenticationMethod.ClientSecretPost) {
      return clientAuthenticationClientSecretPost(options)(callbackOptions)
    }

    if (method === SupportedClientAuthenticationMethod.None) {
      return clientAuthenticationNone(options)(callbackOptions)
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
  authorizationServerMetadata: AuthorizationServerMetadata

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
  options: ClientAuthenticationClientSecretBasicOptions
): ClientAuthenticationCallback {
  return ({ headers }) => {
    const authorization = encodeToBase64Url(decodeUtf8String(`${options.clientId}:${options.clientSecret}`))
    headers.set('Authorization', `Basic ${authorization}`)
  }
}

export interface ClientAuthenticationNoneOptions {
  clientId: string
}

/**
 * Client authentication using `none` option
 */
export function clientAuthenticationNone(options: ClientAuthenticationNoneOptions): ClientAuthenticationCallback {
  return ({ body }) => {
    body.client_id = options.clientId
  }
}

/**
 * Anonymous client authentication
 */
export function clientAuthenticationAnonymous(): ClientAuthenticationCallback {
  return () => {}
}

export interface ClientAuthenticationClientAttestationJwtOptions {
  clientAttestationJwt: string
  callbacks: Pick<CallbackContext, 'signJwt' | 'generateRandom'>
}

/**
 * Client authentication using `attest_jwt_client_auth` option.
 */
export function clientAuthenticationClientAttestationJwt(
  options: ClientAuthenticationClientAttestationJwtOptions
): ClientAuthenticationCallback {
  return async ({ headers, authorizationServerMetadata }) => {
    const clientAttestationPop = await createClientAttestationPopJwt({
      authorizationServer: authorizationServerMetadata.issuer,
      callbacks: options.callbacks,
      clientAttestation: options.clientAttestationJwt,

      // TODO: support client attestation nonce
      // We can fetch it before making the request if we don't have a nonce
      // https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html
      // https://github.com/oauth-wg/draft-ietf-oauth-attestation-based-client-auth/issues/101
      // nonce:
    })

    headers.set(oauthClientAttestationHeader, options.clientAttestationJwt)
    headers.set(oauthClientAttestationPopHeader, clientAttestationPop)
  }
}
