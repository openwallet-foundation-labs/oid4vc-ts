import * as v from 'valibot'
import { vJwtHeader, vJwtPayload } from '../common/jwt/v-jwt'

import { vHttpsUrl, vInteger } from '@animo-id/oauth2-utils'
import { vJwk } from '../common/jwk/v-jwk'

export const vOauthClientAttestationHeader = v.literal('OAuth-Client-Attestation')
export const oauthClientAttestationHeader = vOauthClientAttestationHeader.literal

export const vClientAttestationJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iss: v.string(),
  sub: v.string(),
  exp: vInteger,
  cnf: v.looseObject({
    jwk: vJwk,
    key_type: v.union([
      v.picklist(['software', 'hardware', 'tee', 'secure_enclave', 'strong_box', 'secure_element', 'hsm']),
      v.string(),
    ]),
    user_authentication: v.union([
      v.picklist(['system_biometry', 'system_pin', 'internal_biometry', 'internal_pin', 'secure_element_pin']),
      v.string(),
    ]),
  }),

  aal: v.optional(v.string()),
})
export type ClientAttestationJwtPayload = v.InferOutput<typeof vClientAttestationJwtPayload>

export const vClientAttestationJwtHeader = v.looseObject({
  ...vJwtHeader.entries,
  typ: v.literal('oauth-client-attestation+jwt'),
})
export type ClientAttestationJwtHeader = v.InferOutput<typeof vClientAttestationJwtHeader>

export const vOauthClientAttestationPopHeader = v.literal('OAuth-Client-Attestation-PoP')
export const oauthClientAttestationPopHeader = vOauthClientAttestationPopHeader.literal

export const vClientAttestationPopJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iss: v.string(),
  exp: vInteger,
  aud: vHttpsUrl,

  jti: v.string(),
  nonce: v.optional(v.string()),
})
export type ClientAttestationPopJwtPayload = v.InferOutput<typeof vClientAttestationPopJwtPayload>

export const vClientAttestationPopJwtHeader = v.looseObject({
  ...vJwtHeader.entries,
  typ: v.literal('oauth-client-attestation-pop+jwt'),
})
export type ClientAttestationPopJwtHeader = v.InferOutput<typeof vClientAttestationPopJwtHeader>
