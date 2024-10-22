import * as v from 'valibot'
import { vCompactJwt, vJwk } from '../../../common/validation/v-common'
import { vCredentialRequestProofCommon } from '../../../credential-request/v-proof-type-common'
import { vCredentialIssuerIdentifier } from '../../../metadata/credential-issuer/v-credential-issuer-metadata'

export const vJwtProofTypeIdentifier = v.literal('jwt')
export type JwtProofTypeIdentifier = v.InferOutput<typeof vJwtProofTypeIdentifier>

export const vCredentialRequestProofJwt = v.looseObject({
  ...vCredentialRequestProofCommon.entries,
  proof_type: vJwtProofTypeIdentifier,
  jwt: vCompactJwt,
})

// TODO: extend from generic jwt header oject
export const vCredentialRequestJwtProofTypeHeader = v.pipe(
  v.looseObject({
    alg: v.string(),
    typ: v.literal('openid4vci-proof+jwt'),

    kid: v.optional(v.string()),
    jwk: v.optional(vJwk),
    x5c: v.optional(v.array(v.string())),
    trust_chain: v.optional(v.array(v.string())),
  }),
  v.check(
    ({ kid, jwk }) => jwk !== undefined && kid !== undefined,
    `Both 'jwk' and 'kid' are defined. Only one is allowed`
  ),
  v.check(
    ({ trust_chain, kid }) => trust_chain !== undefined && kid === undefined,
    `When 'trust_chain' is provided, 'kid' is required`
  )
)
export type CredentialRequestJwtProofTypeHeader = v.InferOutput<typeof vCredentialRequestJwtProofTypeHeader>

// TODO: extend from generic jwt payload object
export const vCredentialRequestJwtProofTypePayload = v.looseObject({
  iss: v.optional(v.string()),
  aud: vCredentialIssuerIdentifier,
  iat: v.pipe(v.number(), v.integer()),
  nonce: v.optional(v.string()),
})
export type CredentialRequestJwtProofTypePayload = v.InferOutput<typeof vCredentialRequestJwtProofTypePayload>
