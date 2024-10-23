import * as v from 'valibot'
import { vInteger } from '../../../common/validation/v-common'
import { vCredentialIssuerIdentifier } from '../../../metadata/credential-issuer/v-credential-issuer-metadata'
import { vCompactJwt, vJwtHeader, vJwtPayload } from '../../../common/jwt/v-jwt'

export const vJwtProofTypeIdentifier = v.literal('jwt')
export type JwtProofTypeIdentifier = v.InferOutput<typeof vJwtProofTypeIdentifier>

export const vCredentialRequestProofJwt = v.looseObject({
  proof_type: vJwtProofTypeIdentifier,
  jwt: vCompactJwt,
})

export const vCredentialRequestJwtProofTypeHeader = v.pipe(
  v.looseObject({
    ...vJwtHeader.entries,
    typ: v.literal('openid4vci-proof+jwt'),
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

export const vCredentialRequestJwtProofTypePayload = v.looseObject({
  ...vJwtPayload.entries,
  aud: vCredentialIssuerIdentifier,
  iat: vInteger,
})

export type CredentialRequestJwtProofTypePayload = v.InferOutput<typeof vCredentialRequestJwtProofTypePayload>
