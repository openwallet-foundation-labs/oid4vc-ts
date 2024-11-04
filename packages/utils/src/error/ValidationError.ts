import type * as v from 'valibot'
import { valibotRecursiveFlattenIssues } from '../parse'

export class ValidationError<
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  Schema extends v.BaseSchema<any, any, any> = v.BaseSchema<any, any, any>,
> extends Error {
  public constructor(
    message: string,
    public readonly valibotIssues: Array<v.InferIssue<Schema>> = []
  ) {
    const errorDetails =
      valibotIssues.length > 0
        ? JSON.stringify(valibotRecursiveFlattenIssues(valibotIssues), null, 2)
        : 'No details provided'
    super(`${message}\n${errorDetails}`)
  }
}
