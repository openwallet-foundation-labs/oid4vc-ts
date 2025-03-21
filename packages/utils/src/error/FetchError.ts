export class FetchError extends Error {
  public readonly cause?: Error

  public constructor(message: string, { cause }: { cause?: Error } = {}) {
    super(`${message}\nCause: ${cause?.message}`)
    this.cause = cause
  }
}
