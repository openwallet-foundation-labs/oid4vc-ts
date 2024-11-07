export interface Oid4vciErrorOptions {
  cause?: unknown
}

export class Oid4vciError extends Error {
  public readonly cause?: unknown

  public constructor(message?: string, options?: Oid4vciErrorOptions) {
    const errorMessage = message ?? 'Unknown error occured.'
    const causeMessage =
      options?.cause instanceof Error ? ` ${options.cause.message}` : options?.cause ? ` ${options?.cause}` : ''

    super(`${errorMessage}${causeMessage}`)
    this.cause = options?.cause
  }
}
