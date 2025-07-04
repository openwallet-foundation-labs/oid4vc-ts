import { formatZodError } from '@openid4vc/utils'
import type { RetrieveCredentialsResponseNotOk } from '../credential-request/retrieve-credentials'
import { Openid4vciError } from './Openid4vciError'

export class Openid4vciRetrieveCredentialsError extends Openid4vciError {
  public constructor(
    message: string,
    public response: RetrieveCredentialsResponseNotOk,
    responseText: string
  ) {
    const errorData =
      response.credentialResponseResult?.data ??
      response.credentialErrorResponseResult?.data ??
      (response.credentialResponseResult?.error
        ? formatZodError(response.credentialResponseResult.error)
        : undefined) ??
      responseText

    super(`${message}\n${JSON.stringify(errorData, null, 2)}`)
  }
}
