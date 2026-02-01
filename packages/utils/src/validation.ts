import z from 'zod'
import { getGlobalConfig } from './config'

export const zHttpsUrl = z.url().refine(
  (url) => {
    const { allowInsecureUrls } = getGlobalConfig()
    return allowInsecureUrls ? url.startsWith('http://') || url.startsWith('https://') : url.startsWith('https://')
  },
  { message: 'url must be an https:// url' }
)

export const zDataUrl = z.string().regex(/data:[\w/\-.]+;\w+,.*/, 'url must be a data URL')

export const zInteger = z.number().int()

/**
 * NumericDate as defined in RFC 7519 Section 2
 * A JSON numeric value representing the number of seconds from
 * 1970-01-01T00:00:00Z UTC until the specified UTC date/time,
 * ignoring leap seconds. Non-integer values can be represented.
 */
export const zNumericDate = z.number()

export const zHttpMethod = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = z.infer<typeof zHttpMethod>

export const zStringToJson = z.string().transform((string, ctx) => {
  try {
    return JSON.parse(string)
  } catch (_error) {
    ctx.addIssue({
      code: 'custom',
      message: 'Expected a JSON string, but could not parse the string to JSON',
    })
    return z.NEVER
  }
})

export const zIs = <Schema extends z.ZodSchema>(schema: Schema, data: unknown): data is z.infer<typeof schema> =>
  schema.safeParse(data).success
