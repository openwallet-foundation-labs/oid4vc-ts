import * as v from 'valibot'

export const vCompactJwe = v.pipe(
  v.string(),
  v.regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'Not a valid compact jwe')
)
