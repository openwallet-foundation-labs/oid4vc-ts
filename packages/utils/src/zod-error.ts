import z from 'zod'
import { createErrorMap, fromError } from 'zod-validation-error'

z.config({
  customError: createErrorMap(),
})

export function formatZodError(error?: z.ZodError): string {
  if (!error) return ''

  return fromError(error, { prefix: '', prefixSeparator: '✖ ', issueSeparator: '\n✖ ' }).toString()
}
