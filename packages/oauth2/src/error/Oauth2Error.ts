export interface Oauth2ErrorOptions {
  cause?: unknown
}

export class Oauth2Error extends Error {
  public readonly cause?: unknown

  public constructor(message?: string, options?: Oauth2ErrorOptions) {
    const errorMessage = message ?? 'Unknown error occured.'
    const causeMessage =
      options?.cause instanceof Error ? ` ${options.cause.message}` : options?.cause ? ` ${options?.cause}` : ''

    super(`${errorMessage}${causeMessage}`)
    this.cause = options?.cause
  }
}
