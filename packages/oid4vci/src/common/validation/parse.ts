import * as v from 'valibot'
import { Oid4vcValidationError } from '../../error/Oid4vcValidationError'
import type { BaseSchema } from './v-common'
import { Oid4vcJsonParseError } from '../../error/Oid4vcJsonParseError'

export function stringToJsonWithErrorHandling(string: string, errorMessage?: string) {
  try {
    return JSON.parse(string)
  } catch (error) {
    throw new Oid4vcJsonParseError(errorMessage ?? 'Unable to parse string to JSON.', string)
  }
}

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): v.InferOutput<Schema> {
  const parseResult = v.safeParse(schema, data)

  if (!parseResult.success) {
    throw new Oid4vcValidationError(
      customErrorMessage ?? `Error validating schema with data ${JSON.stringify(data)}`,
      parseResult.issues
    )
  }

  return parseResult.output
}
