export class Oid4vcInvalidFetchResponseError extends Error {
  public readonly response: Response

  public constructor(
    message: string,
    public readonly textResponse: string,
    response: Response
  ) {
    super(`${message}\n${textResponse}`)
    this.response = response.clone()
  }
}
