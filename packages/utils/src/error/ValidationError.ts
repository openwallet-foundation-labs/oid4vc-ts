import type z from 'zod'

export class ValidationError<Schema extends z.ZodTypeAny = z.ZodTypeAny> extends Error {
  public constructor(
    message: string,
    public readonly error?: z.ZodError<Schema>
  ) {
    /**
     * TODO: Before Zod, we were using some flattening logic to make the error message more readable.
     * We may want to do the same thing here again.
     */
    const errorDetails = JSON.stringify(error, null, 2)
    super(`${message}\n${errorDetails}`)
  }
}
