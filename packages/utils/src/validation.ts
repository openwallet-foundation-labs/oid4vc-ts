import * as v from 'valibot'

export const vHttpsUrl = v.pipe(v.string(), v.url(), v.startsWith('https://'))
export const vInteger = v.pipe(v.number(), v.integer())

export const vHttpMethod = v.picklist(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH'])
export type HttpMethod = v.InferOutput<typeof vHttpMethod>
