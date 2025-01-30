import { JsonParseError } from './error/JsonParseError'
import { ValidationError } from './error/ValidationError'
import type z from 'zod'

export type BaseSchema = z.ZodTypeAny
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
export type InferOutputUnion<T extends readonly any[]> = {
  [K in keyof T]: z.infer<T[K]>
}[number]

export function stringToJsonWithErrorHandling(string: string, errorMessage?: string) {
  try {
    return JSON.parse(string)
  } catch (error) {
    throw new JsonParseError(errorMessage ?? 'Unable to parse string to JSON.', string)
  }
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
