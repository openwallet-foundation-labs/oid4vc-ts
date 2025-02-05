import { Oauth2Error, zCompactJwe, zCompactJwt } from '@openid4vc/oauth2'
import { ContentType, URLSearchParams } from '@openid4vc/utils'
export async function parseJarmAuthResponseDirectPostJwt(request: Request) {
  const contentType = request.headers.get('content-type')

  if (!contentType) {
    throw new Oauth2Error('Content type is missing in jarm-request.')
  }

  if (!contentType.includes(ContentType.XWwwFormUrlencoded)) {
    throw new Oauth2Error(
      `Received invalid JARM auth request. Expected content-type application/x-www-form-urlencoded. Current: ${contentType}`
    )
  }

  const formData = await request.clone().text()
  const urlSearchParams = new URLSearchParams(formData)
  const requestData = Object.fromEntries(urlSearchParams)

  if (!requestData.response) {
    throw new Oauth2Error('Received invalid JARM request data. Response Jwt is missing.')
  }

  const isCompactJwt = zCompactJwt.safeParse(requestData.response)
  if (isCompactJwt.success) {
    return { jarmAuthResponseJwt: requestData.response }
  }

  const isCompactJwe = zCompactJwe.safeParse(requestData.response)
  if (isCompactJwe.success) {
    return { jarmAuthResponseJwt: requestData.response }
  }

  throw new Oauth2Error('Received invalid JARM auth response. Expected JWE or JWS.', {
    cause: requestData,
  })
}
