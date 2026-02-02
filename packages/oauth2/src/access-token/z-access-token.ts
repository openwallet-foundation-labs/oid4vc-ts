import { zHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'
import {
  zAuthorizationCodeGrantIdentifier,
  zClientCredentialsGrantIdentifier,
  zPreAuthorizedCodeGrantIdentifier,
  zRefreshTokenGrantIdentifier,
} from '../z-grant-type'

export const zAccessTokenRequest = z.intersection(
  z
    .object({
      // Pre authorized code flow
      'pre-authorized_code': z.optional(z.string()),

      // Authorization code flow
      code: z.optional(z.string()),
      redirect_uri: z.url().optional(),

      // Refresh token grant
      refresh_token: z.optional(z.string()),

      resource: z.optional(zHttpsUrl),
      code_verifier: z.optional(z.string()),

      grant_type: z.union([
        zPreAuthorizedCodeGrantIdentifier,
        zAuthorizationCodeGrantIdentifier,
        zRefreshTokenGrantIdentifier,
        zClientCredentialsGrantIdentifier,
        // string makes the previous ones unnecessary, but it does help with error messages
        z.string(),
      ]),
    })
    .loose(),
  z
    .object({
      tx_code: z.optional(z.string()),
      // user_pin is from OpenID4VCI draft 11
      user_pin: z.optional(z.string()),
    })
    .loose()
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
export type AccessTokenRequest = z.infer<typeof zAccessTokenRequest>

export const zAccessTokenResponse = z
  .object({
    access_token: z.string(),
    token_type: z.string(),

    expires_in: z.optional(z.number().int()),
    scope: z.optional(z.string()),
    state: z.optional(z.string()),

    refresh_token: z.optional(z.string()),

    // OpenID4VCI specific parameters
    c_nonce: z.optional(z.string()),
    c_nonce_expires_in: z.optional(z.number().int()),

    // TODO: add additional params
    authorization_details: z
      .array(
        z
          .object({
            // required when type is openid_credential (so we probably need a discriminator)
            // credential_identifiers: z.array(z.string()),
          })
          .loose()
      )
      .optional(),
  })
  .loose()

export type AccessTokenResponse = z.infer<typeof zAccessTokenResponse>

export const zAccessTokenErrorResponse = zOauth2ErrorResponse
export type AccessTokenErrorResponse = z.infer<typeof zAccessTokenErrorResponse>
