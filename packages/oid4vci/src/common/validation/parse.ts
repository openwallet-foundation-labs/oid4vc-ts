import * as v from 'valibot'
import { Oid4vcValidationError } from '../../error/Oid4vcValidationError'
import type { BaseSchema } from './v-common'

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): v.InferOutput<Schema> {
  const parseResult = v.safeParse(schema, data)

  if (!parseResult.success) {
    throw new Oid4vcValidationError(
      customErrorMessage ?? `Error validating schema with data ${data}`,
      parseResult.issues
    )
  }

  return parseResult.output
}
