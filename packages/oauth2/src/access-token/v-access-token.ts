import * as v from 'valibot'

import { vHttpsUrl } from '@animo-id/oauth2-utils'
import { vOauth2ErrorResponse } from '../common/v-oauth2-error'
import {
  vAuthorizationCodeGrantIdentifier,
  vPreAuthorizedCodeGrantIdentifier,
  vRefreshTokenGrantIdentifier,
} from '../v-grant-type'

export const vAccessTokenRequest = v.intersect([
  v.looseObject({
    // Pre authorized code flow
    'pre-authorized_code': v.optional(v.string()),

    // Authorization code flow
    code: v.optional(v.string()),
    redirect_uri: v.optional(v.pipe(v.string(), v.url())),

    // Refresh token grant
    refresh_token: v.optional(v.string()),

    resource: v.optional(vHttpsUrl),
    code_verifier: v.optional(v.string()),

    grant_type: v.union([
      vPreAuthorizedCodeGrantIdentifier,
      vAuthorizationCodeGrantIdentifier,
      vRefreshTokenGrantIdentifier,
      // string makes the previous ones unessary, but it does help with error messages
      v.string(),
    ]),
  }),
  v.pipe(
    v.looseObject({
      tx_code: v.optional(v.string()),
      // user_pin is from OID4VCI draft 11
      user_pin: v.optional(v.string()),
    }),
    // Check that user_pin and tx_code are the same if both are provided
    // and transform user_pin to tx_code if only user_pin is provided
    v.check(
      ({ tx_code, user_pin }) => !tx_code || !user_pin || user_pin === tx_code,
      `If both 'tx_code' and 'user_pin' are present they must match`
    ),
    v.transform(({ tx_code, user_pin, ...rest }) => {
      return {
        ...rest,
        ...((tx_code ?? user_pin) ? { tx_code: tx_code ?? user_pin } : {}),
      }
    })
  ),
])
export type AccessTokenRequest = v.InferOutput<typeof vAccessTokenRequest>

export const vAccessTokenResponse = v.looseObject({
  access_token: v.string(),
  token_type: v.string(),

  expires_in: v.optional(v.pipe(v.number(), v.integer())),
  scope: v.optional(v.string()),
  state: v.optional(v.string()),

  refresh_token: v.optional(v.string()),

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
