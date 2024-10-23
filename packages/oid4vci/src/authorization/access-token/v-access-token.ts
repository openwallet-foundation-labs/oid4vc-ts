import * as v from 'valibot'
import { vOauth2ErrorResponse } from '../../common/v-oauth2-error'
import {
  vAuthorizationCodeGrantIdentifier,
  vPreAuthorizedCodeGrantIdentifier,
} from '../../credential-offer/v-credential-offer'
import { vHttpsUrl } from '../../common/validation/v-common'

export const vAccessTokenRequest = v.looseObject({
  // Pre authorized code flow
  'pre-authorized_code': v.optional(v.string()),
  tx_code: v.optional(v.string()),

  // Authorization code flow
  code: v.optional(v.string()),
  redirect_uri: v.optional(vHttpsUrl),

  code_verifier: v.optional(v.string()),

  grant_type: v.union([
    vPreAuthorizedCodeGrantIdentifier,
    vAuthorizationCodeGrantIdentifier,
    // string makes the previous ones unessary, but it does help with error messages
    v.string(),
  ]),
})
export type AccessTokenRequest = v.InferOutput<typeof vAccessTokenRequest>

export const vAccessTokenRequestDraft14To11 = v.pipe(
  vAccessTokenRequest,
  v.transform(({ tx_code, ...rest }) => ({
    ...rest,
    ...(tx_code ? { user_pin: tx_code } : {}),
  }))
)

export const vAccessTokenResponse = v.looseObject({
  access_token: v.string(),
  token_type: v.string(),

  expires_in: v.optional(v.pipe(v.number(), v.integer())),
  scope: v.optional(v.string()),
  state: v.optional(v.string()),

  // Oid4vci specific parameters
  c_nonce: v.optional(v.string()),
  c_nonce_expires_in: v.optional(v.pipe(v.number(), v.integer())),
  // TODO: add additional params
  authorization_details: v.optional(
    v.array(
      v.looseObject({
        // requried when type is openid_credential (so we probably need a discriminator)
        // credential_identifiers: v.array(v.string()),
      })
    )
  ),
})
export type AccessTokenResponse = v.InferOutput<typeof vAccessTokenResponse>

export const vAccessTokenErrorResponse = vOauth2ErrorResponse
export type AccessTokenErrorResponse = v.InferOutput<typeof vAccessTokenErrorResponse>
