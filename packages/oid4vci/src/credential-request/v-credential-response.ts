import * as v from 'valibot'
import { vOauth2ErrorResponse } from '../../../oauth2/src/common/v-oauth2-error'

const vCredentialEncoding = v.union([v.string(), v.record(v.string(), v.any())])

export const vCredentialResponse = v.pipe(
  v.looseObject({
    credential: v.optional(vCredentialEncoding),
    credentials: v.optional(v.array(vCredentialEncoding)),

    transaction_id: v.optional(v.string()),

    c_nonce: v.optional(v.string()),
    c_nonce_expires_in: v.optional(v.pipe(v.number(), v.integer())),

    notification_id: v.optional(v.string()),
  }),
  v.check(
    ({ credential, credentials, transaction_id }) =>
      [credential, credentials, transaction_id].filter((i) => i !== undefined).length === 1,
    `Exactly one of 'credential', 'credentials', or 'transaction_id' MUST be defined.`
  )
)
export type CredentialResponse = v.InferOutput<typeof vCredentialResponse>

export const vCredentialErrorResponse = v.looseObject({
  ...vOauth2ErrorResponse.entries,

  c_nonce: v.optional(v.string()),
  c_nonce_expires_in: v.optional(v.pipe(v.number(), v.integer())),
})
export type CredentialErrorResponse = v.InferOutput<typeof vCredentialErrorResponse>
