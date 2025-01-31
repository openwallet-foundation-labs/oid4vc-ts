import type z from 'zod'
import { fromError } from 'zod-validation-error'

export class ValidationError extends Error {
  public constructor(
    message: string,
    public readonly error?: z.ZodError
  ) {
    const errorDetails = fromError(error, {
      issueSeparator: '\n\t- ',
      prefix: `[ValidationError] ${message}`,
      prefixSeparator: '\n\t- ',
    })

    super(errorDetails.toString(), { cause: error })
  }
}
