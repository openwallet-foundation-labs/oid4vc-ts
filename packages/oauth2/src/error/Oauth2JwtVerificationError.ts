import { Oauth2Error, type Oauth2ErrorOptions } from './Oauth2Error'

export class Oauth2JwtVerificationError extends Oauth2Error {
  public constructor(message?: string, options?: Oauth2ErrorOptions) {
    const errorMessage = message ?? 'Error verifiying jwt.'

    super(errorMessage, options)
  }
}
