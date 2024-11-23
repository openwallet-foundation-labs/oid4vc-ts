import * as v from 'valibot'

import { vJwk, vJwtHeader, vJwtPayload } from '@animo-id/oauth2'
import { vInteger } from '@animo-id/oauth2-utils'

export type KeyAttestationJwtUse = 'proof_type.jwt' | 'proof_type.attestation'

export const vKeyAttestationJwtHeader = v.pipe(
  v.looseObject({
    ...vJwtHeader.entries,
    typ: v.literal('keyattestation+jwt'),
  }),
  v.check(
    ({ kid, jwk }) => jwk === undefined || kid === undefined,
    `Both 'jwk' and 'kid' are defined. Only one is allowed`
  ),
  v.check(({ trust_chain, kid }) => !trust_chain || !kid, `When 'trust_chain' is provided, 'kid' is required`)
)
export type KeyAttestationJwtHeader = v.InferOutput<typeof vKeyAttestationJwtHeader>

export const vIso18045 = v.picklist([
  'iso_18045_high',
  'iso_18045_moderate',
  'iso_18045_enhanced-basic',
  'iso_18045_basic',
])

export type Iso18045 = v.InferOutput<typeof vIso18045>
export const vIso18045OrStringArray = v.array(v.union([vIso18045, v.string()]))

export const vKeyAttestationJwtPayload = v.looseObject({
  ...vJwtPayload.entries,
  iat: vInteger,

  attested_keys: v.array(vJwk),
  key_storage: v.optional(vIso18045OrStringArray),
  user_authentication: v.optional(vIso18045OrStringArray),
  certification: v.optional(v.string()),
})

export const vKeyAttestationJwtPayloadForUse = <Use extends KeyAttestationJwtUse | undefined>(use?: Use) =>
  v.looseObject({
    ...vKeyAttestationJwtPayload.entries,

    // REQUIRED when used as proof_type.attesation directly
    nonce:
      use === 'proof_type.attestation'
        ? v.string(`Nonce must be defined when key attestation is used as 'proof_type.attestation' directly`)
        : v.optional(v.string()),

    // REQUIRED when used within header of proof_type.jwt
    exp: use === 'proof_type.jwt' ? vInteger : v.optional(vInteger),
  })

export type KeyAttestationJwtPayload = v.InferOutput<typeof vKeyAttestationJwtPayload>
