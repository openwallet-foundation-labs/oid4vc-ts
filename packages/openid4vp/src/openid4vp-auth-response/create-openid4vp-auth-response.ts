import { type CallbackContext, type JwtSigner, Oauth2Error } from '@openid4vc/oauth2'
import { createJarmAuthResponse } from '../jarm/jarm-auth-response-create'
import { extractJwksFromClientMetadata } from '../jarm/jarm-extract-jwks'
import { jarmAssertMetadataSupported } from '../jarm/metadata/jarm-assert-metadata-supported.js'
import type { JarmServerMetadata } from '../jarm/metadata/v-jarm-as-metadata'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response'

export async function createOpenid4vpAuthorizationResponse(options: {
  requestParams: Pick<Openid4vpAuthRequest, 'state' | 'client_metadata' | 'nonce' | 'response_mode'>
  responseParams: Openid4vpAuthResponse & { state?: never }
  jarm?: {
    jwtSigner?: JwtSigner
    jweEncryptor?: {
      nonce: string
    }
    serverMetadata: JarmServerMetadata
    iss?: string // The issuer URL of the authorization server that created the response
    aud?: string // The client_id of the client the response is intended for
    exp?: number // The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
  }
  callbacks: Pick<CallbackContext, 'signJwt' | 'encryptJwe'>
}) {
  const { requestParams, responseParams, jarm, callbacks } = options

  const openid4vpAuthResponseParams = {
    ...responseParams,
    state: requestParams.state,
  } satisfies Openid4vpAuthResponse

  if (!requestParams.response_mode.includes('jwt')) {
    return { responseParams: openid4vpAuthResponseParams }
  }

  if (!jarm) {
    throw new Oauth2Error(`JARM is required for response mode ${requestParams.response_mode}`)
  }

  if (!requestParams.client_metadata) {
    throw new Oauth2Error('Missing client metadata in the request params to assert JARM metadata support.')
  }

  if (!requestParams.client_metadata.jwks) {
    throw new Oauth2Error('Missing JWKS in client metadata. Cannot extract encryption JWK.')
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
    throw new Oauth2Error('Could not extract encryption JWK from client metadata. Failed to create JARM response.')
  }

  // When the response is NOT only encrypted, the JWT payload needs to include the iss, aud and exp.
  let additionalJwtPayload: Record<string, string | number> | undefined
  if (jarm.jwtSigner) {
    if (!jarm.iss) {
      throw new Oauth2Error('Missing required iss in JARM configuration for creating OpenID4VP authorization response.')
    }

    if (!jarm.aud) {
      throw new Oauth2Error('Missing required aud in JARM configuration for creating OpenID4VP authorization response.')
    }

    additionalJwtPayload = {
      iss: jarm.iss,
      aud: jarm.aud,
      exp: jarm.exp ?? Math.floor(Date.now() / 1000) + 60 * 10, // default: 10 minutes
    }
  }

  const jarmResponseParams = {
    ...openid4vpAuthResponseParams,
    ...additionalJwtPayload,
  } satisfies Openid4vpAuthResponse

  const result = await createJarmAuthResponse({
    jarmAuthResponse: jarmResponseParams,
    jwtSigner: jarm.jwtSigner,
    jwtEncryptor:
      jarm.jweEncryptor && (supportedJarmMetadata.type === 'encrypt' || supportedJarmMetadata.type === 'sign_encrypt')
        ? {
            method: 'jwk',
            publicJwk: clientMetaJwks.encJwk,
            apu: jarm.jweEncryptor.nonce,
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
  }
}
