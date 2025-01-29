import type { FetchHeaders, HttpMethod } from '@openid4vc/utils'
import z from 'zod'

export const vAlgValueNotNone = z.string().refine((alg) => alg !== 'none', { message: `alg value may not be 'none'` })

export interface RequestLike {
  headers: FetchHeaders
  method: HttpMethod
  url: string
}
