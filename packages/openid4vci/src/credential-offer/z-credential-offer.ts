import {
  type AuthorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '@openid4vc/oauth2'
import { zHttpsUrl } from '@openid4vc/utils'
import z from 'zod'

const zTxCode = z
  .object({
    input_mode: z.union([z.literal('numeric'), z.literal('text')]).optional(),
    length: z.number().int().optional(),
    description: z.string().max(300).optional(),
  })
  .passthrough()

export type CredentialOfferPreAuthorizedCodeGrantTxCode = z.input<typeof zTxCode>

export const zCredentialOfferGrants = z
  .object({
    authorization_code: z
      .object({
        issuer_state: z.string().optional(),
        authorization_server: zHttpsUrl.optional(),
      })
      .passthrough()
      .optional(),
    [preAuthorizedCodeGrantIdentifier]: z
      .object({
        'pre-authorized_code': z.string(),
        tx_code: zTxCode.optional(),
        authorization_server: zHttpsUrl.optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()

export type CredentialOfferGrants = z.input<typeof zCredentialOfferGrants>

export type CredentialOfferPreAuthorizedCodeGrant = CredentialOfferGrants[PreAuthorizedCodeGrantIdentifier]
export type CredentialOfferAuthorizationCodeGrant = CredentialOfferGrants[AuthorizationCodeGrantIdentifier]

const zCredentialOfferObjectDraft14 = z
  .object({
    credential_issuer: zHttpsUrl,
    credential_configuration_ids: z.array(z.string()),
    grants: z.optional(zCredentialOfferGrants),
  })
  .passthrough()
export type CredentialOfferObject = z.input<typeof zCredentialOfferObjectDraft14>

export const zCredentialOfferObjectDraft11To14 = z
  .object({
    credential_issuer: zHttpsUrl,
    // We don't support the inline offer objects from draft 11
    credentials: z.array(
      z.string({ message: 'Only string credential identifiers are supported for draft 11 credential offers' })
    ),
    grants: z.optional(
      z.object({
        // Has extra param in draft 14, but doesn't matter for transform purposes
        authorization_code: zCredentialOfferGrants.shape.authorization_code,

        [preAuthorizedCodeGrantIdentifier]: z
          .object({
            'pre-authorized_code': z.string(),
            user_pin_required: z.optional(z.boolean()),
          })
          .passthrough()
          .optional(),
      })
    ),
  })
  .passthrough()
  .transform(({ credentials, grants, ...rest }) => {
    const v14: CredentialOfferObject = {
      ...rest,
      credential_configuration_ids: credentials,
    }

    if (grants) {
      v14.grants = { ...grants }

      if (grants[preAuthorizedCodeGrantIdentifier]) {
        const { user_pin_required, ...restGrants } = grants[preAuthorizedCodeGrantIdentifier]

        v14.grants[preAuthorizedCodeGrantIdentifier] = {
          ...restGrants,
        }

        if (user_pin_required) {
          v14.grants[preAuthorizedCodeGrantIdentifier].tx_code = {
            input_mode: 'text',
          }
        }
      }
    }

    return v14
  })
  .pipe(zCredentialOfferObjectDraft14)

export const zCredentialOfferObject = z.union([
  // First prioritize draft 14 (and 13)
  zCredentialOfferObjectDraft14,
  // Then try parsing draft 11 and transform into draft 14
  zCredentialOfferObjectDraft11To14,
])
