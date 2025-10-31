import { URL } from '@openid4vc/utils'
import z from 'zod'
import { zOauth2ErrorResponse } from '../common/z-oauth2-error'

export const zAuthorizationResponse = z
  .object({
    state: z.string().optional(),
    code: z.string().nonempty(),

    // This allows for discriminating between error and success responses.
    error: z.optional(z.never()),
  })
  .loose()

export const zAuthorizationResponseFromUriParams = z
  .url()
  .transform((url): unknown => Object.fromEntries(new URL(url).searchParams))
  .pipe(zAuthorizationResponse)

export type AuthorizationResponse = z.infer<typeof zAuthorizationResponse>

export const zAuthorizationErrorResponse = z
  .object({
    ...zOauth2ErrorResponse.shape,
    state: z.string().optional(),

    // This allows for discriminating between error and success responses.
    code: z.optional(z.never()),
  })
  .loose()
export type AuthorizationErrorResponse = z.infer<typeof zAuthorizationErrorResponse>
