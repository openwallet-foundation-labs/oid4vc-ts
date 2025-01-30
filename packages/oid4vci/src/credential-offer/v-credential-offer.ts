import {
  type AuthorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '@openid4vc/oauth2'
import z from 'zod'
import { vHttpsUrl } from '../../../utils/src/validation'

const vTxCode = z
  .object({
    input_mode: z.union([z.literal('numeric'), z.literal('text')]).optional(),
    length: z.number().int().optional(),
    description: z.string().max(300).optional(),
  })
  .passthrough()

export type CredentialOfferPreAuthorizedCodeGrantTxCode = z.input<typeof vTxCode>

export const vCredentialOfferGrants = z
  .object({
    authorization_code: z
      .object({
        issuer_state: z.string().optional(),
        authorization_server: vHttpsUrl.optional(),
      })
      .passthrough()
      .optional(),
    [preAuthorizedCodeGrantIdentifier]: z
      .object({
        'pre-authorized_code': z.string(),
        tx_code: vTxCode.optional(),
        authorization_server: vHttpsUrl.optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()

export type CredentialOfferGrants = z.input<typeof vCredentialOfferGrants>

export type CredentialOfferPreAuthorizedCodeGrant = CredentialOfferGrants[PreAuthorizedCodeGrantIdentifier]
export type CredenialOfferAuthorizationCodeGrant = CredentialOfferGrants[AuthorizationCodeGrantIdentifier]

const vCredentialOfferObjectDraft14 = z
  .object({
    credential_issuer: vHttpsUrl,
    credential_configuration_ids: z.array(z.string()),
    grants: z.optional(vCredentialOfferGrants),
  })
  .passthrough()
export type CredentialOfferObject = z.input<typeof vCredentialOfferObjectDraft14>

export const vCredentialOfferObjectDraft11To14 = z
  .object({
    credential_issuer: vHttpsUrl,
    // We don't support the inline offer objects from draft 11
    credentials: z.array(
      z.string({ message: 'Only string credential identifiers are supported for draft 11 credential offers' })
    ),
    grants: z.optional(
      z.object({
        // Has extra param in draft 14, but doesn't matter for transform purposes
        authorization_code: vCredentialOfferGrants.shape.authorization_code,

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
  .pipe(vCredentialOfferObjectDraft14)

export const vCredentialOfferObject = z.union([
  // First prioritize draft 14 (and 13)
  vCredentialOfferObjectDraft14,
  // Then try parsing draft 11 and transform into draft 14
  vCredentialOfferObjectDraft11To14,
])
