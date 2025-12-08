export abstract class OpenId4VcError extends Error {
  public constructor(message: string) {
    super(message)
  }
}