import {
  type AuthorizationCodeGrantIdentifier,
  type PreAuthorizedCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from '@animo-id/oauth2'
import { vHttpsUrl } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'

export const vCredentialOfferGrants = v.looseObject({
  authorization_code: v.optional(
    v.looseObject({
      issuer_state: v.optional(v.string()),
      authorization_server: v.optional(vHttpsUrl),
    })
  ),

  [preAuthorizedCodeGrantIdentifier]: v.optional(
    v.looseObject({
      'pre-authorized_code': v.string(),
      tx_code: v.optional(
        v.looseObject({
          input_mode: v.optional(v.union([v.literal('numeric'), v.literal('text')]), 'numeric'),
          length: v.optional(v.pipe(v.number(), v.integer())),
          description: v.optional(v.pipe(v.string(), v.maxLength(300))),
        })
      ),
      authorization_server: v.optional(vHttpsUrl),
    })
  ),
})
export type CredentialOfferGrants = v.InferInput<typeof vCredentialOfferGrants>
export type CredentialOfferPreAuthorizedCodeGrant = CredentialOfferGrants[PreAuthorizedCodeGrantIdentifier]
export type CredenialOfferAuthorizationCodeGrant = CredentialOfferGrants[AuthorizationCodeGrantIdentifier]

const vCredentialOfferObjectDraft14 = v.looseObject({
  credential_issuer: vHttpsUrl,
  credential_configuration_ids: v.array(v.string()),
  grants: v.optional(vCredentialOfferGrants),
})
export type CredentialOfferObject = v.InferInput<typeof vCredentialOfferObjectDraft14>

export const vCredentialOfferObjectDraft11To14 = v.pipe(
  v.looseObject({
    credential_issuer: vHttpsUrl,
    // We don't support the inline offer objects from draft 11
    credentials: v.array(v.string(), 'Only string credential identifiers are supported for draft 11 credential offers'),
    grants: v.optional(
      v.looseObject({
        // Has extra param in draft 14, but doesn't matter for transform purposes
        authorization_code: vCredentialOfferGrants.entries.authorization_code,

        [preAuthorizedCodeGrantIdentifier]: v.optional(
          v.looseObject({
            'pre-authorized_code': v.string(),
            user_pin_required: v.optional(v.boolean()),
          })
        ),
      })
    ),
  }),
  v.transform(({ credentials, grants, ...rest }) => {
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
  }),
  vCredentialOfferObjectDraft14
)

export const vCredentialOfferObject = v.union([
  // First prioritize draft 14 (and 13)
  vCredentialOfferObjectDraft14,
  // Then try parsing draft 11 and transform into draft 14
  vCredentialOfferObjectDraft11To14,
])
