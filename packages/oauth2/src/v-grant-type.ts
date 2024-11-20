import * as v from 'valibot'

export const vPreAuthorizedCodeGrantIdentifier = v.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code')
export const preAuthorizedCodeGrantIdentifier = vPreAuthorizedCodeGrantIdentifier.literal
export type PreAuthorizedCodeGrantIdentifier = v.InferOutput<typeof vPreAuthorizedCodeGrantIdentifier>

export const vAuthorizationCodeGrantIdentifier = v.literal('authorization_code')
export const authorizationCodeGrantIdentifier = vAuthorizationCodeGrantIdentifier.literal
export type AuthorizationCodeGrantIdentifier = v.InferOutput<typeof vAuthorizationCodeGrantIdentifier>

export const vRefreshTokenGrantIdentifier = v.literal('refresh_token')
export const refreshTokenGrantIdentifier = vRefreshTokenGrantIdentifier.literal
export type RefreshTokenGrantIdentifier = v.InferOutput<typeof vRefreshTokenGrantIdentifier>
