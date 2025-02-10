import { Oauth2Error } from '@openid4vc/oauth2'
import { dateToSeconds } from '@openid4vc/utils'
import { type JarmAuthResponse, type JarmAuthResponseEncryptedOnly, zJarmAuthResponse } from './z-jarm-auth-response'

export const jarmAuthResponseValidate = (options: {
  authRequest: { client_id: string }
  authResponse: JarmAuthResponse | JarmAuthResponseEncryptedOnly
}) => {
  const { authRequest, authResponse } = options

  // The traditional Jarm Validation Methods do not account for the encrypted response.
  if (!zJarmAuthResponse.safeParse(authResponse).success) {
    return
  }

  // 3. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequest.client_id !== authResponse.aud) {
    throw new Oauth2Error(
      `Invalid 'aud' claim in JARM authorization response. Expected '${
        authRequest.client_id
      }' received '${JSON.stringify(authResponse.aud)}'.`
    )
  }

  // 4. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (authResponse.exp !== undefined && authResponse.exp < dateToSeconds()) {
    throw new Oauth2Error('Jarm auth response is expired.')
  }
}
