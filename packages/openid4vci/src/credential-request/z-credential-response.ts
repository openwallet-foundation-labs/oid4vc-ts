import z from 'zod'
import { zOauth2ErrorResponse } from '../../../oauth2/src/common/z-oauth2-error'

const zCredentialEncoding = z.union([z.string(), z.record(z.string(), z.any())])

const zBaseCredentialResponse = z
  .object({
    credentials: z
      .union([
        // Draft >= 15
        z.array(z.object({ credential: zCredentialEncoding })),
        // Draft < 15
        z.array(zCredentialEncoding),
      ])
      .optional(),
    interval: z.number().int().positive().optional(),
    notification_id: z.string().optional(),
  })
  .loose()

export const zCredentialResponse = zBaseCredentialResponse
  .extend({
    credential: z.optional(zCredentialEncoding),
    transaction_id: z.string().optional(),

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .loose()
  .superRefine((value, ctx) => {
    const { credential, credentials, transaction_id, interval, notification_id } = value

    if ([credential, credentials, transaction_id].filter((i) => i !== undefined).length !== 1) {
      ctx.addIssue({
        code: 'custom',
        message: `Exactly one of 'credential', 'credentials', or 'transaction_id' MUST be defined.`,
      })
    }

    if (transaction_id && !interval) {
      ctx.addIssue({
        code: 'custom',
        message: `'interval' MUST be defined when 'transaction_id' is defined.`,
      })
    }

    if (notification_id && !(credentials || credential)) {
      ctx.addIssue({
        code: 'custom',
        message: `'notification_id' MUST NOT be defined when 'credential' or 'credentials' are not defined.`,
      })
    }
  })

export type CredentialResponse = z.infer<typeof zCredentialResponse>

export const zCredentialErrorResponse = z
  .object({
    ...zOauth2ErrorResponse.shape,

    c_nonce: z.string().optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .loose()

export type CredentialErrorResponse = z.infer<typeof zCredentialErrorResponse>

export const zDeferredCredentialResponse = zBaseCredentialResponse.refine(
  (value) => {
    const { credentials, interval } = value
    return [credentials, interval].filter((i) => i !== undefined).length === 1
  },
  {
    message: `Exactly one of 'credentials' or 'interval' MUST be defined.`,
  }
)

export type DeferredCredentialResponse = z.infer<typeof zDeferredCredentialResponse>
