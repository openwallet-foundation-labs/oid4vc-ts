import z from 'zod'
import { zOauth2ErrorResponse } from '../../../oauth2/src/common/z-oauth2-error'

const zCredentialEncoding = z.union([z.string(), z.record(z.string(), z.any())])

export const zCredentialResponse = z
  .object({
    credential: z.optional(zCredentialEncoding),
    credentials: z.optional(z.array(zCredentialEncoding)),

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

export type CredentialResponse = z.infer<typeof zCredentialResponse>

export const zCredentialErrorResponse = z
  .object({
    ...zOauth2ErrorResponse.shape,

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .passthrough()

export type CredentialErrorResponse = z.infer<typeof zCredentialErrorResponse>
