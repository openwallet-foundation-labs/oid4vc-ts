import {
  type CallbackContext,
  type JwtSigner,
  Oauth2Error,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '@openid4vc/oauth2'
import { dateToSeconds } from '@openid4vc/utils'
import { addSecondsToDate } from '../../../utils/src/date'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { isOpenid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { createJarmAuthResponse } from '../jarm/jarm-auth-response-create'
import { extractJwksFromClientMetadata } from '../jarm/jarm-extract-jwks'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { jarmAssertMetadataSupported } from '../jarm/metadata/jarm-assert-metadata-supported'
import type { JarmServerMetadata } from '../jarm/metadata/z-jarm-authorization-server-metadata'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'
import type { Openid4vpAuthorizationResponseDcApi } from './z-authorization-response-dc-api'

export interface CreateOpenid4vpAuthorizationResponseOptions {
  requestParams:
    | Pick<Openid4vpAuthorizationRequest, 'state' | 'client_metadata' | 'nonce' | 'response_mode'>
    | Pick<Openid4vpAuthorizationRequestDcApi, 'client_metadata' | 'response_mode' | 'nonce'>
  responseParams: (Openid4vpAuthorizationResponse | Openid4vpAuthorizationResponseDcApi['data']) & { state?: never }
  jarm?: {
    jwtSigner?: JwtSigner
    encryption?: { nonce: string }
    serverMetadata: JarmServerMetadata
    authorizationServer?: string // The issuer URL of the authorization server that created the response
    audience?: string // The client_id of the client the response is intended for
    expiresInSeconds?: number // The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
  }
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}

export interface CreateOpenid4vpAuthorizationResponseResult {
  responseParams: Openid4vpAuthorizationResponse | Openid4vpAuthorizationResponseDcApi['data']
  jarm?: { responseJwt: string }
  dcApiResponseParams?: Openid4vpAuthorizationResponseDcApi
}

export async function createOpenid4vpAuthorizationResponse(
  options: CreateOpenid4vpAuthorizationResponseOptions
): Promise<CreateOpenid4vpAuthorizationResponseResult> {
  const { requestParams, responseParams, jarm, callbacks } = options
  const openid4vpAuthResponseParams = {
    ...responseParams,
    ...('state' in requestParams && { state: requestParams.state }),
  } satisfies Openid4vpAuthorizationResponse | Openid4vpAuthorizationResponseDcApi

  if (requestParams.response_mode && isJarmResponseMode(requestParams.response_mode) && !jarm) {
    throw new Oauth2Error(
      `Missing jarm options for creating Jarm response with response mode '${requestParams.response_mode}'`
    )
  }

  if (!jarm) {
    return {
      responseParams: openid4vpAuthResponseParams,
      ...(isOpenid4vpAuthorizationRequestDcApi(openid4vpAuthResponseParams) && {
        dcApiResponseParams: {
          protocol: 'openid4vp',
          data: openid4vpAuthResponseParams,
        },
      }),
    }
  }

  if (!requestParams.client_metadata) {
    throw new Oauth2Error('Missing client metadata in the request params to assert Jarm metadata support.')
  }

  if (!requestParams.client_metadata.jwks) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'Missing JWKS in client metadata. Cannot extract encryption JWK.',
    })
  }

  const supportedJarmMetadata = jarmAssertMetadataSupported({
    clientMetadata: requestParams.client_metadata,
    serverMetadata: jarm.serverMetadata,
  })

  const clientMetaJwks = extractJwksFromClientMetadata({
    ...requestParams.client_metadata,
    jwks: requestParams.client_metadata.jwks,
  })

  if (!clientMetaJwks?.encJwk) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'Could not extract encryption JWK from client metadata. Failed to create JARM response.',
    })
  }

  // When the response is NOT only encrypted, the JWT payload needs to include the iss, aud and exp.
  let additionalJwtPayload: Record<string, string | number> | undefined
  if (jarm?.jwtSigner) {
    if (!jarm.authorizationServer) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Missing required iss in JARM configuration for creating OpenID4VP authorization response.',
      })
    }

    if (!jarm.audience) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: 'Missing required aud in JARM configuration for creating OpenID4VP authorization response.',
      })
    }

    additionalJwtPayload = {
      iss: jarm.authorizationServer,
      aud: jarm.audience,
      exp: jarm.expiresInSeconds ?? dateToSeconds(addSecondsToDate(new Date(), 60 * 10)), // default: 10 minutes
    }
  }

  const jarmResponseParams = {
    ...openid4vpAuthResponseParams,
    ...additionalJwtPayload,
  } satisfies Openid4vpAuthorizationResponse

  const result = await createJarmAuthResponse({
    jarmAuthResponse: jarmResponseParams,
    jwtSigner: jarm?.jwtSigner,
    jwtEncryptor:
      jarm?.encryption && (supportedJarmMetadata.type === 'encrypt' || supportedJarmMetadata.type === 'sign_encrypt')
        ? {
            method: 'jwk',
            publicJwk: clientMetaJwks.encJwk,
            apu: jarm.encryption?.nonce,
            apv: requestParams.nonce,
            alg: supportedJarmMetadata.client_metadata.authorization_encrypted_response_alg,
            enc: supportedJarmMetadata.client_metadata.authorization_encrypted_response_enc,
          }
        : undefined,
    callbacks: {
      signJwt: callbacks.signJwt,
      encryptJwe: callbacks.encryptJwe,
    },
  })

  return {
    responseParams: jarmResponseParams,
    jarm: { responseJwt: result.jarmAuthResponseJwt },
    ...(isOpenid4vpAuthorizationRequestDcApi(openid4vpAuthResponseParams) && {
      dcApiResponseParams: {
        protocol: 'openid4vp',
        data: jarmResponseParams,
      },
    }),
  }
}
