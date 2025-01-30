import { vOauth2ErrorResponse } from '../../../oauth2/src/common/v-oauth2-error'
import z from 'zod'

const vCredentialEncoding = z.union([z.string(), z.record(z.string(), z.any())])

export const vCredentialResponse = z
  .object({
    credential: z.optional(vCredentialEncoding),
    credentials: z.optional(z.array(vCredentialEncoding)),

    transaction_id: z.string().optional(),

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().int().optional(),

    notification_id: z.string().optional(),
  })
  .passthrough()
  .refine(
    (value) => {
      const { credential, credentials, transaction_id } = value
      return [credential, credentials, transaction_id].filter((i) => i !== undefined).length === 1
    },
    {
      message: `Exactly one of 'credential', 'credentials', or 'transaction_id' MUST be defined.`,
    }
  )

export type CredentialResponse = z.infer<typeof vCredentialResponse>

export const vCredentialErrorResponse = z
  .object({
    ...vOauth2ErrorResponse.shape,

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .passthrough()

export type CredentialErrorResponse = z.infer<typeof vCredentialErrorResponse>
