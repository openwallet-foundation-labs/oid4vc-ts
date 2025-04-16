import { ContentType, isResponseContentType } from '../content-type'
import type { FetchResponse } from '../globals'

export class InvalidFetchResponseError extends Error {
  public readonly response: FetchResponse

  public constructor(
    message: string,
    public readonly textResponse: string,
    response: FetchResponse
  ) {
    // We don't want to put html content in pages. For other content we take the first 1000 characters
    // to prevent ridiculously long errors.
    const textResponseMessage = isResponseContentType(ContentType.Html, response)
      ? undefined
      : textResponse.substring(0, 1000)

    super(textResponseMessage ? `${message}\n${textResponseMessage}` : message)

    this.response = response.clone()
  }
}
