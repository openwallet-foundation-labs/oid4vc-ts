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
