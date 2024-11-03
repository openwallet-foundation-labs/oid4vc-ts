import type { FetchHeaders, HttpMethod } from '@animo-id/oid4vc-utils'
import * as v from 'valibot'

export const vAlgValueNotNone = v.pipe(
  v.string(),
  v.check((alg: string) => alg !== 'none', `alg value may not be 'none'`)
)

export interface RequestLike {
  headers: FetchHeaders
  method: HttpMethod
  url: string
}
