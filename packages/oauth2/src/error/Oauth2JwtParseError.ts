import { Oauth2Error } from './Oauth2Error'

export class Oauth2JwtParseError extends Oauth2Error {
  public constructor(message?: string) {
    const errorMessage = message ?? 'Error parsing jwt'

    super(errorMessage)
  }
}
