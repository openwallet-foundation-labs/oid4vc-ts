import type { ZodError } from 'zod'
import { formatZodError } from '../zod-error'
import { OpenId4VcBaseError } from './OpenId4VcBaseError'

export class ValidationError extends OpenId4VcBaseError {
  public zodError: ZodError | undefined

  constructor(message: string, zodError?: ZodError) {
    super(message)

    const formattedError = zodError ? formatZodError(zodError) : ''
    this.message = `${message}\n${formattedError}`

    Object.defineProperty(this, 'zodError', {
      value: zodError,
      writable: false,
      enumerable: false,
    })
  }
}
