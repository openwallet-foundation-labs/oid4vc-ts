import { Oauth2Error, vCompactJwe, vCompactJwt } from '@openid4vc/oauth2'
import { ContentType, URLSearchParams } from '@openid4vc/utils'
import * as v from 'valibot'

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

  if (v.is(vCompactJwt, requestData.response)) {
    return { jarmAuthResponseJwt: requestData.response }
  }

  if (v.is(vCompactJwe, requestData.response)) {
    return { jarmAuthResponseJwt: requestData.response }
  }

  throw new Oauth2Error('Received invalid JARM auth response. Expected JWE or JWS.', {
    cause: requestData,
  })
}
