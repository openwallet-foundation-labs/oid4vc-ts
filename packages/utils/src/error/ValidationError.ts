import type { ZodError, z } from 'zod'
import { formatZodError } from '../zod-error'

export class ValidationError extends Error {
  public zodError: ZodError | undefined

  constructor(message: string, zodError?: z.ZodError) {
    super(message)

    const formattedError = formatZodError(zodError)
    this.message = `${message}\n${formattedError}`

    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}
