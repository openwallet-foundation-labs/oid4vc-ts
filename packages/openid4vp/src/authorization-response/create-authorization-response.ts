import {
  type CallbackContext,
  type JwkSet,
  type JwtSigner,
  Oauth2Error,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
  fetchJwks,
} from '@openid4vc/oauth2'
import { dateToSeconds } from '@openid4vc/utils'
import { addSecondsToDate } from '../../../utils/src/date'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { getOpenid4vpClientId } from '../client-identifier-scheme/parse-client-identifier-scheme'
import { createJarmAuthorizationResponse } from '../jarm/jarm-authorization-response-create'
import { extractJwksFromClientMetadata } from '../jarm/jarm-extract-jwks'
import { isJarmResponseMode } from '../jarm/jarm-response-mode'
import { jarmAssertMetadataSupported } from '../jarm/metadata/jarm-assert-metadata-supported'
import type { JarmServerMetadata } from '../jarm/metadata/z-jarm-authorization-server-metadata'
import type { ClientMetadata } from '../models/z-client-metadata'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface CreateOpenid4vpAuthorizationResponseOptions {
  authorizationRequestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi

  /**
   * Optional client metadata to use for sending the authorization response. In case of e.g. OpenID Federation
   * the client metadata needs to be resolved and verified externally.
   */
  clientMetadata?: ClientMetadata

  /**
   * The origin of the reuqest, required when creating a response for the Digital Credentials API.
   */
  origin?: string

  authorizationResponsePayload: Openid4vpAuthorizationResponse & { state?: never }
  jarm?: {
    jwtSigner?: JwtSigner
    encryption?: { nonce: string }
    serverMetadata: JarmServerMetadata
    authorizationServer?: string // The issuer URL of the authorization server that created the response
    audience?: string // The client_id of the client the response is intended for
    expiresInSeconds?: number // The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
  }
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe' | 'fetch'>
}

export interface CreateOpenid4vpAuthorizationResponseResult {
  authorizationResponsePayload: Openid4vpAuthorizationResponse
  jarm?: { responseJwt: string }
}

export async function createOpenid4vpAuthorizationResponse(
  options: CreateOpenid4vpAuthorizationResponseOptions
): Promise<CreateOpenid4vpAuthorizationResponseResult> {
  const { authorizationRequestPayload, jarm, callbacks, origin } = options

  const authorizationResponsePayload = {
    ...options.authorizationResponsePayload,
    state: authorizationRequestPayload.state,
  } satisfies Openid4vpAuthorizationResponse

  const { clientIdScheme } = getOpenid4vpClientId({
    responseMode: authorizationRequestPayload.response_mode,
    clientId: authorizationRequestPayload.client_id,
    legacyClientIdScheme: authorizationRequestPayload.client_id_scheme,
    origin,
  })

  if (
    authorizationRequestPayload.response_mode &&
    isJarmResponseMode(authorizationRequestPayload.response_mode) &&
    !jarm
  ) {
    throw new Oauth2Error(
      `Missing jarm options for creating Jarm response with response mode '${authorizationRequestPayload.response_mode}'`
    )
  }

  if (!jarm) {
    return {
      authorizationResponsePayload,
    }
  }

  // When using OpenID Federation, we must not rely on the client metadata from the request
  if (clientIdScheme === 'https' && !options.clientMetadata) {
    throw new Oauth2Error(
      "When OpenID Federation is used as the client id scheme (https), passing externally fetched and verified 'clientMetadata' to the 'createOpenid4vpAuthorizationResponse' is required."
    )
  }

  const clientMetadata = options.clientMetadata ?? authorizationRequestPayload.client_metadata
  if (!clientMetadata) {
    throw new Oauth2Error('Missing client metadata in the request params to assert Jarm metadata support.')
  }

  let jwks: JwkSet

  if (clientMetadata.jwks) {
    jwks = clientMetadata.jwks
  } else if (clientMetadata.jwks_uri) {
    jwks = await fetchJwks(clientMetadata.jwks_uri, options.callbacks.fetch)
  } else {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `Missing 'jwks' or 'jwks_uri' in client metadata. Cannot extract encryption JWK.`,
    })
  }

  const supportedJarmMetadata = jarmAssertMetadataSupported({
    clientMetadata: clientMetadata,
    serverMetadata: jarm.serverMetadata,
  })

  const clientMetaJwks = extractJwksFromClientMetadata({
    ...clientMetadata,
    jwks,
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

  const jarmResponsePayload = {
    ...authorizationResponsePayload,
    ...additionalJwtPayload,
  } satisfies Openid4vpAuthorizationResponse

  const result = await createJarmAuthorizationResponse({
    jarmAuthorizationResponse: jarmResponsePayload,
    jwtSigner: jarm?.jwtSigner,
    jweEncryptor:
      jarm?.encryption && (supportedJarmMetadata.type === 'encrypt' || supportedJarmMetadata.type === 'sign_encrypt')
        ? {
            method: 'jwk',
            publicJwk: clientMetaJwks.encJwk,
            apu: jarm.encryption?.nonce,
            apv: authorizationRequestPayload.nonce,
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
    authorizationResponsePayload: jarmResponsePayload,
    jarm: { responseJwt: result.jarmAuthorizationResponseJwt },
  }
}
