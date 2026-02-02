import z from 'zod'

export const zPreAuthorizedCodeGrantIdentifier = z.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code')
export const preAuthorizedCodeGrantIdentifier = zPreAuthorizedCodeGrantIdentifier.value
export type PreAuthorizedCodeGrantIdentifier = z.infer<typeof zPreAuthorizedCodeGrantIdentifier>

export const zAuthorizationCodeGrantIdentifier = z.literal('authorization_code')
export const authorizationCodeGrantIdentifier = zAuthorizationCodeGrantIdentifier.value
export type AuthorizationCodeGrantIdentifier = z.infer<typeof zAuthorizationCodeGrantIdentifier>

export const zRefreshTokenGrantIdentifier = z.literal('refresh_token')
export const refreshTokenGrantIdentifier = zRefreshTokenGrantIdentifier.value
export type RefreshTokenGrantIdentifier = z.infer<typeof zRefreshTokenGrantIdentifier>

/**
 * Default value for `grant_types_supported` per RFC 8414 Section 2
 * when not explicitly provided in authorization server metadata.
 */
export const defaultGrantTypesSupported = [authorizationCodeGrantIdentifier, 'implicit'] as const

/**
 * Get the supported grant types from authorization server metadata,
 * falling back to the RFC 8414 default of `["authorization_code", "implicit"]`.
 */
export function getGrantTypesSupported(grantTypesSupported: string[] | undefined): readonly string[] {
  return grantTypesSupported ?? defaultGrantTypesSupported
}

export const zClientCredentialsGrantIdentifier = z.literal('client_credentials')
export const clientCredentialsGrantIdentifier = zClientCredentialsGrantIdentifier.value
export type ClientCredentialsGrantIdentifier = z.infer<typeof zClientCredentialsGrantIdentifier>
