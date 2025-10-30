import { Oauth2Error } from '@openid4vc/oauth2'
import { dateToSeconds } from '@openid4vc/utils'
import {
  type JarmAuthorizationResponse,
  type JarmAuthorizationResponseEncryptedOnly,
  zJarmAuthorizationResponse,
} from './z-jarm-authorization-response'

export const jarmAuthorizationResponseValidate = (options: {
  expectedClientId: string
  authorizationResponse: JarmAuthorizationResponse | JarmAuthorizationResponseEncryptedOnly
}) => {
  const { expectedClientId, authorizationResponse } = options

  // The traditional Jarm Validation Methods do not account for the encrypted response.
  if (!zJarmAuthorizationResponse.safeParse(authorizationResponse).success) {
    return
  }

  // 3. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (
    (Array.isArray(authorizationResponse.aud) && !authorizationResponse.aud.includes(expectedClientId)) ||
    (typeof authorizationResponse.aud === 'string' && authorizationResponse.aud !== expectedClientId)
  ) {
    throw new Oauth2Error(
      `Invalid 'aud' claim in JARM authorization response. Expected '${
        expectedClientId
      }' received '${JSON.stringify(authorizationResponse.aud)}'.`
    )
  }

  // 4. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (authorizationResponse.exp !== undefined && authorizationResponse.exp < dateToSeconds()) {
    throw new Oauth2Error('JARM auth response is expired.')
  }
}
