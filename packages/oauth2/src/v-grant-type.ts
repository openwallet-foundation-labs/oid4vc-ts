import * as v from 'valibot'

export const vPreAuthorizedCodeGrantIdentifier = v.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code')
export const preAuthorizedCodeGrantIdentifier = vPreAuthorizedCodeGrantIdentifier.literal
export type PreAuthorizedCodeGrantIdentifier = v.InferOutput<typeof vPreAuthorizedCodeGrantIdentifier>

export const vAuthorizationCodeGrantIdentifier = v.literal('authorization_code')
export const authorizationCodeGrantIdentifier = vAuthorizationCodeGrantIdentifier.literal
export type AuthorizationCodeGrantIdentifier = v.InferOutput<typeof vAuthorizationCodeGrantIdentifier>
