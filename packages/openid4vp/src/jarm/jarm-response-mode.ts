import { z } from 'zod'

export const jarmResponseMode = [
  'jwt',
  'query.jwt',
  'fragment.jwt',
  'form_post.jwt',
  'direct_post.jwt',
  'dc_api.jwt',
] as const
export const zJarmResponseMode = z.enum(jarmResponseMode)

export type JarmResponseMode = (typeof jarmResponseMode)[number]

export const isJarmResponseMode = (responseMode: string): responseMode is JarmResponseMode => {
  return jarmResponseMode.includes(responseMode as JarmResponseMode)
}
