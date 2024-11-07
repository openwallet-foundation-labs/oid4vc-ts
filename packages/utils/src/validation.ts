import * as v from 'valibot'
import { getGlobalConfig } from './config'

export const vHttpsUrl = v.pipe(
  v.string(),
  v.url(),
  v.check((url) => {
    const { allowInsecureUrls } = getGlobalConfig()
    return allowInsecureUrls ? url.startsWith('http://') || url.startsWith('https://') : url.startsWith('https://')
  }, 'url must be an https:// url')
)
export const vInteger = v.pipe(v.number(), v.integer())

export const vHttpMethod = v.picklist(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = v.InferOutput<typeof vHttpMethod>
