import z from 'zod'
import { getGlobalConfig } from './config'

export const vHttpsUrl = z
  .string()
  .url()
  .refine(
    (url) => {
      const { allowInsecureUrls } = getGlobalConfig()
      return allowInsecureUrls ? url.startsWith('http://') || url.startsWith('https://') : url.startsWith('https://')
    },
    { message: 'url must be an https:// url' }
  )

export const vInteger = z.number().int()

export const vHttpMethod = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = z.infer<typeof vHttpMethod>

export const zIs = <Schema extends z.ZodSchema>(schema: Schema, data: unknown): data is z.infer<typeof schema> =>
  schema.safeParse(data).success
