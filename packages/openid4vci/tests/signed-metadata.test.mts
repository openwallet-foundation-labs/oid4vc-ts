import {
  decodeJwt,
  Oauth2AuthorizationServer,
  PkceCodeChallengeMethod,
  SupportedClientAuthenticationMethod,
} from '@openid4vc/oauth2'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { getSignJwtCallback, callbacks as partialCallbacks } from '../../oauth2/tests/util.mjs'
import { type CredentialConfigurationSupportedWithFormats, Openid4vciClient, Openid4vciIssuer } from '../src/index.js'

const credentialIssuerJwk = {
  kty: 'EC',
  d: 'IfSdct8njqWDcMaLIO3ZGG-8a61t9acXxxFWFVDFx6Y',
  crv: 'P-256',
  x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
  y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
}
const { d: __, ...credentialIssuerJwkPublic } = credentialIssuerJwk

const server = setupServer()

const callbacks = {
  ...partialCallbacks,
  fetch,
  signJwt: getSignJwtCallback([credentialIssuerJwk]),
}

const issuer = new Openid4vciIssuer({
  callbacks,
})
const client = new Openid4vciClient({
  callbacks,
})
const authorizationServer = new Oauth2AuthorizationServer({ callbacks })

const authorizationServerMetadata = authorizationServer.createAuthorizationServerMetadata({
  issuer: 'https://oauth2-auth-server.com',
  token_endpoint: 'https://oauth2-auth-server.com/token',
  authorization_endpoint: 'https://oauth2-auth-server.com/authorize',
  jwks_uri: 'https://oauth2-auth-server.com/jwks.json',
  dpop_signing_alg_values_supported: ['ES256'],
  // TODO: verify this on the server
  require_pushed_authorization_requests: true,
  pushed_authorization_request_endpoint: 'https://oauth2-auth-server.com/par',
  code_challenge_methods_supported: [PkceCodeChallengeMethod.S256],
  token_endpoint_auth_methods_supported: [SupportedClientAuthenticationMethod.ClientAttestationJwt],
})

const credentialConfigurationsSupported = {
  pidSdJwt: {
    format: 'vc+sd-jwt',
    vct: 'https://sd-jwt.com',
    credential_signing_alg_values_supported: ['ES256'],
    cryptographic_binding_methods_supported: ['jwk'],
    proof_types_supported: {
      jwt: {
        proof_signing_alg_values_supported: ['ES256'],
      },
    },
    scope: 'PidSdJwt',
  },
} satisfies Record<string, CredentialConfigurationSupportedWithFormats>

const credentialIssuerMetadata = issuer.createCredentialIssuerMetadata({
  credential_issuer: 'https://oid4vc-ts-issuer.com',
  credential_endpoint: 'https://oid4vc-ts-issuer.com/credential',
  credential_configurations_supported: credentialConfigurationsSupported,
  authorization_servers: [authorizationServerMetadata.issuer],
})

describe('Signed Credential Issuer Metadata', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('Create, resolve and verify signed credential issuer metadata', async () => {
    const credentialIssuerMetadataJwt = await issuer.createSignedCredentialIssuerMetadataJwt({
      credentialIssuerMetadata,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialIssuerJwkPublic,
      },
    })

    expect(decodeJwt({ jwt: credentialIssuerMetadataJwt })).toStrictEqual({
      compact: credentialIssuerMetadataJwt,
      signature: expect.any(String),
      header: {
        alg: 'ES256',
        jwk: {
          crv: 'P-256',
          kty: 'EC',
          x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
          y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
        },
        typ: 'openidvci-issuer-metadata+jwt',
      },
      payload: {
        ...credentialIssuerMetadata,
        iat: expect.any(Number),
        sub: credentialIssuerMetadata.credential_issuer,
      },
    })

    server.resetHandlers(
      http.get(`${credentialIssuerMetadata.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.text(credentialIssuerMetadataJwt, { headers: { 'Content-Type': 'application/jwt' } })
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/openid-configuration`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.json(authorizationServerMetadata)
      )
    )

    // Overwrite for the mock
    callbacks.fetch = fetch

    const resolvedIssuerMetadata = await client.resolveIssuerMetadata(credentialIssuerMetadata.credential_issuer)
    expect(resolvedIssuerMetadata.credentialIssuer.credential_issuer).toStrictEqual(
      credentialIssuerMetadata.credential_issuer
    )

    expect(resolvedIssuerMetadata.signedCredentialIssuer).toStrictEqual({
      jwt: {
        compact: credentialIssuerMetadataJwt,
        signature: expect.any(String),
        header: {
          alg: 'ES256',
          jwk: {
            crv: 'P-256',
            kty: 'EC',
            x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
            y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
          },
          typ: 'openidvci-issuer-metadata+jwt',
        },
        payload: {
          ...credentialIssuerMetadata,
          iat: expect.any(Number),
          sub: credentialIssuerMetadata.credential_issuer,
        },
      },
      signer: {
        alg: 'ES256',
        method: 'jwk',
        publicJwk: {
          crv: 'P-256',
          kty: 'EC',
          x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
          y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
        },
      },
    })
  })
})
