import z from 'zod'
import { getGlobalConfig } from './config'

export const zHttpsUrl = z.url().refine(
  (url) => {
    const { allowInsecureUrls } = getGlobalConfig()
    return allowInsecureUrls ? url.startsWith('http://') || url.startsWith('https://') : url.startsWith('https://')
  },
  { message: 'url must be an https:// url' }
)

export const zDataUrl = z
  .string()
  .max(2000)
  .regex(/data:[\w/\-.]+;\w+,.*/, 'url must be a data URL')

export const zInteger = z.number().int()

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
