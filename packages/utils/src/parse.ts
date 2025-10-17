import type z from 'zod'
import { JsonParseError } from './error/JsonParseError'
import { ValidationError } from './error/ValidationError'

export type BaseSchema = z.ZodTypeAny
// biome-ignore lint/suspicious/noExplicitAny: no explanation
export type InferOutputUnion<T extends readonly any[]> = {
  [K in keyof T]: z.infer<T[K]>
}[number]

export function stringToJsonWithErrorHandling(string: string, errorMessage?: string) {
  try {
    return JSON.parse(string)
  } catch (_error) {
    throw new JsonParseError(errorMessage ?? 'Unable to parse string to JSON.', string)
  }
}

export function parseIfJson<T>(data: T): T | Record<string, unknown> {
  if (typeof data !== 'string') {
    return data
  }

  try {
    // Try to parse the string as JSON
    return JSON.parse(data)
  } catch (_error) {}

  return data
}

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): z.infer<Schema> {
  const parseResult = schema.safeParse(data)

  if (!parseResult.success) {
    throw new ValidationError(
      customErrorMessage ?? `Error validating schema with data ${JSON.stringify(data)}`,
      parseResult.error
    )
  }

  return parseResult.data
}
