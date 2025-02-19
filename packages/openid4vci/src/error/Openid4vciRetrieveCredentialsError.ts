import type { RetrieveCredentialsResponseNotOk } from '../credential-request/retrieve-credentials'
import { Openid4vciError } from './Openid4vciError'

export class Openid4vciRetrieveCredentialsError extends Openid4vciError {
  public constructor(
    message: string,
    public response: RetrieveCredentialsResponseNotOk,
    responseText: string
  ) {
    super(
      `${message}\n${JSON.stringify(response.credentialResponseResult?.data ?? response.credentialErrorResponseResult?.data ?? responseText, null, 2)}`
    )
  }
}
