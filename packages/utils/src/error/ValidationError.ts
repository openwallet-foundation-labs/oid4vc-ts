import z, { type ZodError } from 'zod'
import { OpenId4VcBaseError } from './OpenId4VcBaseError'

export class ValidationError extends OpenId4VcBaseError {
  public zodError: ZodError | undefined

  constructor(message: string, zodError?: ZodError) {
    super(message)

    const formattedError = zodError ? z.prettifyError(zodError) : ''
    this.message = `${message}\n${formattedError}`

    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}
