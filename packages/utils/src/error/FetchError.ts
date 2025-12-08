import { OpenId4VcError } from "./OpenId4VcError"

export class FetchError extends OpenId4VcError {
  public readonly cause?: Error

  public constructor(message: string, { cause }: { cause?: Error } = {}) {
    super(`${message}\nCause: ${cause?.message}`)
    this.cause = cause
  }
}
