export interface Oid4vcErrorOptions {
  cause?: unknown
}

export class Oid4vcError extends Error {
  public constructor(message?: string, options?: Oid4vcErrorOptions) {
    const errorMessage = message ?? 'Unknown error occured.'
    const causeMessage = options?.cause instanceof Error ? options.cause.message : options?.cause

    super(`${errorMessage} ${causeMessage}`)
  }
}
