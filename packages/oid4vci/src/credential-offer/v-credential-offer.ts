import * as v from 'valibot'
import { vAuthorizationServerIdentifier } from '../metadata/authorization-server/v-authorization-server-metadata'
import { vCredentialIssuerIdentifier } from '../metadata/credential-issuer/v-credential-issuer-metadata'

export const vPreAuthorizedCodeGrantIdentifier = v.literal('urn:ietf:params:oauth:grant-type:pre-authorized_code')
export const preAuthorizedCodeGrantIdentifier = vPreAuthorizedCodeGrantIdentifier.literal

export const vAuthorizationCodeGrantIdentifier = v.literal('authorization_code')
export const authorizationCodeGrantIdentifier = vAuthorizationCodeGrantIdentifier.literal

export const vCredentialOfferGrants = v.looseObject({
  authorization_code: v.optional(
    v.looseObject({
      issuer_state: v.optional(v.string()),
      authorization_server: v.optional(vAuthorizationServerIdentifier),
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
      authorization_server: v.optional(vAuthorizationServerIdentifier),
    })
  ),
})

export type CredentialOfferObject = v.InferOutput<typeof vCredentialOfferObject>
export const vCredentialOfferObject = v.looseObject({
  credential_issuer: vCredentialIssuerIdentifier,
  credential_configuration_ids: v.array(v.string()),
  grants: v.optional(vCredentialOfferGrants),
})
