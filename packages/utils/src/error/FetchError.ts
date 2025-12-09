import { OpenId4VcBaseError } from './OpenId4VcBaseError'

export class FetchError extends OpenId4VcBaseError {
  public readonly cause?: Error

  public constructor(message: string, { cause }: { cause?: Error } = {}) {
    super(`${message}\nCause: ${cause?.message}`)
    this.cause = cause
  }
}
