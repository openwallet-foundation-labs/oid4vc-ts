import z from 'zod'

import { vHttpsUrl } from '@openid4vc/utils'
import { vOauth2ErrorResponse } from '../common/v-oauth2-error'
import {
  vAuthorizationCodeGrantIdentifier,
  vPreAuthorizedCodeGrantIdentifier,
  vRefreshTokenGrantIdentifier,
} from '../v-grant-type'

export const vAccessTokenRequest = z.intersection(
  z
    .object({
      // Pre authorized code flow
      'pre-authorized_code': z.optional(z.string()),

      // Authorization code flow
      code: z.optional(z.string()),
      redirect_uri: z.string().url().optional(),

      // Refresh token grant
      refresh_token: z.optional(z.string()),

      resource: z.optional(vHttpsUrl),
      code_verifier: z.optional(z.string()),

      grant_type: z.union([
        vPreAuthorizedCodeGrantIdentifier,
        vAuthorizationCodeGrantIdentifier,
        vRefreshTokenGrantIdentifier,
        // string makes the previous ones unessary, but it does help with error messages
        z.string(),
      ]),
    })
    .passthrough(),
  z
    .object({
      tx_code: z.optional(z.string()),
      // user_pin is from OID4VCI draft 11
      user_pin: z.optional(z.string()),
    })
    .passthrough()
    .refine(({ tx_code, user_pin }) => !tx_code || !user_pin || user_pin === tx_code, {
      message: `If both 'tx_code' and 'user_pin' are present they must match`,
    })
    .transform(({ tx_code, user_pin, ...rest }) => {
      return {
        ...rest,
        ...((tx_code ?? user_pin) ? { tx_code: tx_code ?? user_pin } : {}),
      }
    })
)
export type AccessTokenRequest = z.infer<typeof vAccessTokenRequest>

export const vAccessTokenResponse = z
  .object({
    access_token: z.string(),
    token_type: z.string(),

    expires_in: z.optional(z.number().int()),
    scope: z.optional(z.string()),
    state: z.optional(z.string()),

    refresh_token: z.optional(z.string()),

    // Oid4vci specific parameters
    c_nonce: z.optional(z.string()),
    c_nonce_expires_in: z.optional(z.number().int()),

    // TODO: add additional params
    authorization_details: z
      .array(
        z
          .object({
            // requried when type is openid_credential (so we probably need a discriminator)
            // credential_identifiers: z.array(z.string()),
          })
          .passthrough()
      )
      .optional(),
  })
  .passthrough()

export type AccessTokenResponse = z.infer<typeof vAccessTokenResponse>

export const vAccessTokenErrorResponse = vOauth2ErrorResponse
export type AccessTokenErrorResponse = z.infer<typeof vAccessTokenErrorResponse>
