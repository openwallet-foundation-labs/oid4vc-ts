import z from 'zod'

export const vPreAuthorizedCodeGrantIdentifier = z.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code')
export const preAuthorizedCodeGrantIdentifier = vPreAuthorizedCodeGrantIdentifier.value
export type PreAuthorizedCodeGrantIdentifier = z.infer<typeof vPreAuthorizedCodeGrantIdentifier>

export const vAuthorizationCodeGrantIdentifier = z.literal('authorization_code')
export const authorizationCodeGrantIdentifier = vAuthorizationCodeGrantIdentifier.value
export type AuthorizationCodeGrantIdentifier = z.infer<typeof vAuthorizationCodeGrantIdentifier>

export const vRefreshTokenGrantIdentifier = z.literal('refresh_token')
export const refreshTokenGrantIdentifier = vRefreshTokenGrantIdentifier.value
export type RefreshTokenGrantIdentifier = z.infer<typeof vRefreshTokenGrantIdentifier>
