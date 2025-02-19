export interface Openid4vciErrorOptions {
  cause?: unknown
}

export class Openid4vciError extends Error {
  public readonly cause?: unknown

  public constructor(message?: string, options?: Openid4vciErrorOptions) {
    const errorMessage = message ?? 'Unknown error occured.'
    const causeMessage =
      options?.cause instanceof Error ? ` ${options.cause.message}` : options?.cause ? ` ${options?.cause}` : ''

    super(`${errorMessage}${causeMessage}`)
    this.cause = options?.cause
  }
}
