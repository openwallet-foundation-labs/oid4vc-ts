import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError, zCompactJwe, zCompactJwt } from '@openid4vc/oauth2'
import { ContentType, URLSearchParams } from '@openid4vc/utils'
import z from 'zod'

export async function parseJarmAuthorizationResponseDirectPostJwt(request: Request) {
  const contentType = request.headers.get('content-type')

  if (!contentType) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'content-type' header is missing in the JARM authorization response request.`,
    })
  }

  if (!contentType.includes(ContentType.XWwwFormUrlencoded)) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Invalid 'content-type' header in the JARM authorization response request. Expected 'application/x-www-form-urlencoded'.`,
      },
      {
        internalMessage: `Received invalid JARM auth request. Expected content-type application/x-www-form-urlencoded. Current: ${contentType}`,
      }
    )
  }

  const formData = await request.clone().text()
  const urlSearchParams = new URLSearchParams(formData)
  const requestData = Object.fromEntries(urlSearchParams)

  if (!requestData.response) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Invalid JARM authorization response. The required 'response' parameter is missing.`,
    })
  }

  const isJweOrJws = z.union([zCompactJwt, zCompactJwe]).safeParse(requestData.response)
  if (isJweOrJws.success) {
    return { jarmAuthorizationResponseJwt: requestData.response }
  }

  throw new Oauth2ServerErrorResponseError(
    {
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Invalid JARM authorization response. The 'response' parameter is not a valid JWE or JWT.`,
    },
    {
      cause: requestData,
    }
  )
}
