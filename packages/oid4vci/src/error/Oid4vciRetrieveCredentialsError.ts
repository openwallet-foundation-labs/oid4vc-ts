import type { RetrieveCredentialsResponseNotOk } from '../credential-request/retrieve-credentials'
import { Oid4vciError } from './Oid4vciError'

export class Oid4vciRetrieveCredentialsError extends Oid4vciError {
  public constructor(
    message: string,
    public response: RetrieveCredentialsResponseNotOk,
    responseText: string
  ) {
    super(
      `${message}\n${JSON.stringify(response.credentialResponseResult ?? response.credentialErrorResponseResult ?? responseText, null, 2)}`
    )
  }
}
