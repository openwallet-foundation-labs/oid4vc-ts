import {
  HashAlgorithm,
  type Jwk,
  type JwkSet,
  Oauth2AuthorizationServer,
  Oauth2Client,
  Oauth2ResourceServer,
  PkceCodeChallengeMethod,
  SupportedAuthenticationScheme,
  authorizationCodeGrantIdentifier,
  calculateJwkThumbprint,
  preAuthorizedCodeGrantIdentifier,
} from '@openid4vc/oauth2'
import { ContentType, type HttpMethod, addSecondsToDate, decodeUtf8String, encodeToBase64Url } from '@openid4vc/utils'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { getSignJwtCallback, parseXwwwFormUrlEncoded, callbacks as partialCallbacks } from '../../oauth2/tests/util'
import {
  type CredentialConfigurationSupportedWithFormats,
  Openid4vciClient,
  Openid4vciDraftVersion,
  Openid4vciIssuer,
  Openid4vciWalletProvider,
  extractScopesForCredentialConfigurationIds,
} from '../src'

const dpopJwk = {
  kty: 'EC',
  d: 'IfSdct8njqWDcMaLIO3ZGG-8a61t9acXxxFWFVDFx6Y',
  crv: 'P-256',
  x: 'ghHo8AZRPhIdmR9zO_aab0R7CsDah-XI5zht8GXo71w',
  y: 'Xfx_VfGzNfRVT5cNbi8jKZ3KMgKzqPGHWCT1yklA0UE',
}
const { d: __, ...dpopJwkPublic } = dpopJwk

const credentialRequestProofJwk = {
  kty: 'EC',
  d: 'b3T5vRCtRPk-iWQs1qZiCH8pmfUp3g6HfobJi4gHKX8',
  crv: 'P-256',
  x: 'ILLpnBYABwKEgkSLnX7Py8jP6MpcQO6t5u232iOdcz8',
  y: 'II3uHcxF5ve3VFtUb1ZGWIxVMyLhynRHDnJa2WPXj9E',
}
const { d: __2, ...credentialRequestProofJwkPublic } = credentialRequestProofJwk

const accessTokenJwk = {
  kty: 'EC',
  d: 'Y2KgM6WsS5lAiZMj96VaqPm0YpP67mclJ5yXbhM7oQE',
  crv: 'P-256',
  x: 'kazsvNpTiwE4mB6k-uLHNfexl_UysiJqNvDRO6SZE1A',
  y: 'VnWF5YzCR5ZWiugFM4rxPDviOWmMXU4pUVCRAdz-uLI',
}
const { d: __3, ...accessTokenJwkPublic } = accessTokenJwk

const walletProviderJwk = {
  kty: 'EC',
  d: 'oXYK_EmjSLauIIkWF53DuRhZTx9SHg5lC5eWZmtWPxE',
  crv: 'P-256',
  x: '2l7WpVHYQoWWjHcB9MpfEylT7w-bhRbG3i-38Cel7EI',
  y: 'm5c_gqV2sbLmGh4p1bhEANwyt0xtfacrc554SyomrX0',
}
const { d: __4, ...walletProviderJwkPublic } = walletProviderJwk

const walletConfirmationJwk = {
  kty: 'EC',
  d: 'mGQM_sFuOw-kUvB8oUU0iQSr6AuOG0hCLyvGRHdfK-s',
  crv: 'P-256',
  x: 'mYgFqhj2fISu1V4UhrIwg5VJ1fdVzaGRsneZR7hsgkk',
  y: 'wOZREecqelO_--lBV9_eQB9NAlhzw0urY5ZEDAoh1e4',
}
const { d: __5, ...walletConfirmationJwkPublic } = walletConfirmationJwk

const server = setupServer()

const callbacks = {
  ...partialCallbacks,
  fetch,
  signJwt: getSignJwtCallback([
    credentialRequestProofJwk,
    dpopJwk,
    accessTokenJwk,
    walletConfirmationJwk,
    walletProviderJwk,
  ]),
}

const issuer = new Openid4vciIssuer({
  callbacks,
})
const client = new Openid4vciClient({
  callbacks,
})
const authorizationServer = new Oauth2AuthorizationServer({ callbacks })
const resourceServer = new Oauth2ResourceServer({ callbacks })
const oauth2Client = new Oauth2Client({ callbacks })
const walletProvider = new Openid4vciWalletProvider({ callbacks })

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

const issuerMetadata = {
  credentialIssuer: credentialIssuerMetadata,
  authorizationServers: [authorizationServerMetadata],
}

describe('Full E2E test', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('full flow of issuance using pre-authorized code', async () => {
    const preAuthorizedCode = '2abe1b25-b51a-4d1f-83ca-968444ad85d0'
    const createdCredentialOffer = await issuer.createCredentialOffer({
      credentialConfigurationIds: Object.keys(credentialConfigurationsSupported),
      grants: {
        [preAuthorizedCodeGrantIdentifier]: { 'pre-authorized_code': preAuthorizedCode },
      },
      issuerMetadata,
      credentialOfferUri: 'https://oid4vc-ts-issuer.com/offers/1f9f284a-3b37-4d92-adb4-6339c9b7ca68',
      credentialOfferScheme: 'https://oid4vc-ts-issuer.com/invitation',
    })

    expect(createdCredentialOffer.credentialOffer).toEqual(
      'https://oid4vc-ts-issuer.com/invitation?credential_offer_uri=https%3A%2F%2Foid4vc-ts-issuer.com%2Foffers%2F1f9f284a-3b37-4d92-adb4-6339c9b7ca68'
    )
    expect(createdCredentialOffer.credentialOfferObject).toEqual({
      credential_configuration_ids: ['pidSdJwt'],
      credential_issuer: 'https://oid4vc-ts-issuer.com',
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': expect.any(String),
        },
      },
    })

    server.resetHandlers(
      http.get('https://oid4vc-ts-issuer.com/offers/1f9f284a-3b37-4d92-adb4-6339c9b7ca68', () =>
        HttpResponse.json(createdCredentialOffer.credentialOfferObject)
      ),
      http.get(`${credentialIssuerMetadata.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.json(credentialIssuerMetadata)
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/openid-configuration`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.json(authorizationServerMetadata)
      ),
      http.get(`${authorizationServerMetadata.jwks_uri}`, () =>
        HttpResponse.json({ keys: [accessTokenJwkPublic] } satisfies JwkSet, {
          headers: { 'Content-Type': ContentType.JwkSet },
        })
      ),
      http.post(authorizationServerMetadata.token_endpoint, async ({ request }) => {
        const accessTokenRequest = parseXwwwFormUrlEncoded(await request.text())
        expect(accessTokenRequest).toEqual({
          'pre-authorized_code': expect.any(String),
          grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
          resource: createdCredentialOffer.credentialOfferObject.credential_issuer,
        })

        const parsedAccessTokenRequest = authorizationServer.parseAccessTokenRequest({
          accessTokenRequest,
          request: {
            headers: request.headers,
            method: request.method as HttpMethod,
            url: request.url,
          },
        })
        expect(parsedAccessTokenRequest).toEqual({
          accessTokenRequest: {
            'pre-authorized_code': preAuthorizedCode,
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            resource: createdCredentialOffer.credentialOfferObject.credential_issuer,
          },
          grant: {
            grantType: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            preAuthorizedCode: preAuthorizedCode,
            txCode: undefined,
          },
          dpopJwt: expect.any(String),
          pkceCodeVerifier: undefined,
        })

        if (parsedAccessTokenRequest.grant.grantType !== preAuthorizedCodeGrantIdentifier) {
          return HttpResponse.json({
            error: 'invalid_grant',
            error_description: 'grant_type not supported',
          })
        }

        const { dpop } = await authorizationServer.verifyPreAuthorizedCodeAccessTokenRequest({
          grant: parsedAccessTokenRequest.grant,
          accessTokenRequest: parsedAccessTokenRequest.accessTokenRequest,
          expectedPreAuthorizedCode: preAuthorizedCode,
          request: {
            method: request.method as HttpMethod,
            headers: request.headers,
            url: request.url,
          },
          dpop: {
            required: true,
            jwt: parsedAccessTokenRequest.dpopJwt,
          },
        })

        const accessTokenResponse = await authorizationServer.createAccessTokenResponse({
          audience: credentialIssuerMetadata.credential_issuer,
          signer: {
            method: 'jwk',
            alg: 'ES256',
            publicJwk: accessTokenJwkPublic,
          },
          subject: parsedAccessTokenRequest.grant.preAuthorizedCode,
          expiresInSeconds: 300,
          authorizationServer: authorizationServerMetadata.issuer,
          cNonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          cNonceExpiresIn: 100,
          dpopJwk: dpop?.jwk,
          scope: extractScopesForCredentialConfigurationIds({
            issuerMetadata,
            credentialConfigurationIds: createdCredentialOffer.credentialOfferObject.credential_configuration_ids,
            throwOnConfigurationWithoutScope: true,
          })?.join(' '),
        })
        return HttpResponse.json(accessTokenResponse)
      }),
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        const { dpopJwk, tokenPayload } = await resourceServer.verifyResourceRequest({
          authorizationServers: issuerMetadata.authorizationServers,
          request: {
            url: request.url,
            method: request.method as HttpMethod,
            headers: request.headers,
          },
          resourceServer: credentialIssuerMetadata.credential_issuer,
          allowedAuthenticationSchemes: [SupportedAuthenticationScheme.DPoP],
        })

        expect(dpopJwk).toEqual(dpopJwkPublic)
        expect(tokenPayload).toEqual({
          iss: authorizationServerMetadata.issuer,
          aud: credentialIssuerMetadata.credential_issuer,
          iat: expect.any(Number),
          exp: expect.any(Number),
          jti: expect.any(String),
          cnf: {
            jkt: await calculateJwkThumbprint({
              hashAlgorithm: HashAlgorithm.Sha256,
              hashCallback: callbacks.hash,
              jwk: dpopJwk as Jwk,
            }),
          },
          sub: preAuthorizedCode,
          scope: 'PidSdJwt',
        })

        const credentialRequest = await request.json()
        expect(credentialRequest).toEqual({
          format: 'vc+sd-jwt',
          vct: credentialConfigurationsSupported.pidSdJwt.vct,
          proof: {
            proof_type: 'jwt',
            jwt: expect.any(String),
          },
        })

        const parsedCredentialRequest = issuer.parseCredentialRequest({
          issuerMetadata: {
            authorizationServers: [],
            credentialIssuer: credentialIssuerMetadata,
            originalDraftVersion: Openid4vciDraftVersion.Draft14,
          },
          credentialRequest: credentialRequest as Record<string, unknown>,
        })

        if (!parsedCredentialRequest.proofs?.jwt) {
          throw new Error('Missing required jwt proofs')
        }

        const verifiedProof = await issuer.verifyCredentialRequestJwtProof({
          expectedNonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          issuerMetadata,
          jwt: parsedCredentialRequest.proofs.jwt[0],
        })
        expect(verifiedProof).toEqual({
          header: {
            alg: 'ES256',
            typ: 'openid4vci-proof+jwt',
            jwk: credentialRequestProofJwkPublic,
          },
          payload: {
            aud: credentialIssuerMetadata.credential_issuer,
            iat: expect.any(Number),
            nonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          },
          signer: {
            alg: 'ES256',
            method: 'jwk',
            publicJwk: credentialRequestProofJwkPublic,
          },
        })

        expect(parsedCredentialRequest).toEqual({
          format: { format: 'vc+sd-jwt', vct: credentialConfigurationsSupported.pidSdJwt.vct },
          credentialRequest: {
            proof: {
              proof_type: 'jwt',
              jwt: expect.any(String),
            },
            format: 'vc+sd-jwt',
            vct: credentialConfigurationsSupported.pidSdJwt.vct,
          },
          proofs: {
            jwt: [expect.any(String)],
          },
        })

        const credentialResponse = issuer.createCredentialResponse({
          credential: 'some-credential',
          cNonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
          cNonceExpiresInSeconds: 500,
          notificationId: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
          credentialRequest: parsedCredentialRequest,
        })

        return HttpResponse.json(credentialResponse)
      })
    )

    // Overwrite for the mock
    callbacks.fetch = fetch

    const resolvedCredentialOffer = await client.resolveCredentialOffer(createdCredentialOffer.credentialOffer)
    expect(resolvedCredentialOffer).toStrictEqual(createdCredentialOffer.credentialOfferObject)

    const resolvedIssuerMetadata = await client.resolveIssuerMetadata(resolvedCredentialOffer.credential_issuer)
    expect(resolvedIssuerMetadata.credentialIssuer.credential_issuer).toStrictEqual(
      credentialIssuerMetadata.credential_issuer
    )

    // TODO: move this to ??
    const isDpopSupported = oauth2Client.isDpopSupported({
      authorizationServerMetadata,
    })
    expect(isDpopSupported).toEqual({
      supported: true,
      dpopSigningAlgValuesSupported: ['ES256'],
    })

    const {
      accessTokenResponse,
      authorizationServer: authorizationServerIdentifier,
      dpop,
    } = await client.retrievePreAuthorizedCodeAccessTokenFromOffer({
      credentialOffer: resolvedCredentialOffer,
      issuerMetadata,
      // TODO: how to select the alg
      dpop: isDpopSupported
        ? {
            signer: {
              alg: 'ES256',
              method: 'jwk',
              publicJwk: dpopJwkPublic,
            },
          }
        : undefined,
    })
    expect(accessTokenResponse).toStrictEqual({
      access_token: expect.any(String),
      c_nonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
      c_nonce_expires_in: 100,
      expires_in: 300,
      token_type: 'DPoP',
    })
    expect(authorizationServerIdentifier).toStrictEqual(authorizationServerMetadata.issuer)

    const { jwt } = await client.createCredentialRequestJwtProof({
      credentialConfigurationId: resolvedCredentialOffer.credential_configuration_ids[0],
      issuerMetadata,
      // TODO: how to determine supported signer?
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      nonce: accessTokenResponse.c_nonce,
    })

    const credentialResponse = await client.retrieveCredentials({
      issuerMetadata,
      accessToken: accessTokenResponse.access_token,
      credentialConfigurationId: resolvedCredentialOffer.credential_configuration_ids[0],
      dpop,
      proof: {
        proof_type: 'jwt',
        jwt,
      },
    })
    expect(credentialResponse.credentialResponse).toEqual({
      c_nonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
      c_nonce_expires_in: 500,
      credential: 'some-credential',
      notification_id: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
      format: 'vc+sd-jwt',
    })
  })

  test('full flow of issuance using authorization code flow', async () => {
    const walletAttestation = await walletProvider.createWalletAttestationJwt({
      clientId: 'wallet',
      confirmation: {
        jwk: walletConfirmationJwkPublic,
      },
      // Valid one hour
      expiresAt: addSecondsToDate(new Date(), 3600),
      issuer: 'https://wallet-provider.com',
      signer: {
        method: 'jwk',
        publicJwk: walletProviderJwkPublic,
        alg: 'ES256',
      },
      walletLink: 'https://wallet-provider.com/wallet',
      walletName: 'Wallet',
    })

    const createdCredentialOffer = await issuer.createCredentialOffer({
      credentialConfigurationIds: Object.keys(credentialConfigurationsSupported),
      grants: {
        [authorizationCodeGrantIdentifier]: {
          issuer_state: 'something',
        },
      },
      issuerMetadata,
    })

    expect(createdCredentialOffer.credentialOffer).toEqual(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Foid4vc-ts-issuer.com%22%2C%22credential_configuration_ids%22%3A%5B%22pidSdJwt%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22something%22%7D%7D%7D'
    )
    expect(createdCredentialOffer.credentialOfferObject).toEqual({
      credential_configuration_ids: ['pidSdJwt'],
      credential_issuer: credentialIssuerMetadata.credential_issuer,
      grants: {
        authorization_code: {
          issuer_state: 'something',
        },
      },
    })

    server.resetHandlers(
      http.get(`${credentialIssuerMetadata.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.json(credentialIssuerMetadata)
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/openid-configuration`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.get(`${authorizationServerMetadata.issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.json(authorizationServerMetadata)
      ),
      http.get(`${authorizationServerMetadata.jwks_uri}`, () =>
        HttpResponse.json({ keys: [accessTokenJwkPublic] } satisfies JwkSet, {
          headers: { 'Content-Type': ContentType.JwkSet },
        })
      ),
      http.post(`${authorizationServerMetadata.pushed_authorization_request_endpoint}`, async ({ request }) => {
        const parRequest = parseXwwwFormUrlEncoded(await request.text())

        // TODO: (should we make a method verify PAR request to make it easier to handle all these things?)
        // - verify the client attestation sub against the request client_id
        // - need to match dpop key and client attestation key??
        // - add verify pushed authorization request method

        const { authorizationRequest, clientAttestation, dpop } = authorizationServer.parsePushedAuthorizationRequest({
          authorizationRequest: parRequest,
          request: {
            headers: request.headers,
            method: request.method as HttpMethod,
            url: request.url,
          },
        })

        // TODO: add verifyAuthorizationChallengeRequest method that also verifies DPoP and client attestation
        const verifiedParRequest = await authorizationServer.verifyPushedAuthorizationRequest({
          authorizationRequest,
          authorizationServerMetadata,
          request: {
            headers: request.headers,
            method: request.method as HttpMethod,
            url: request.url,
          },
          clientAttestation,
          dpop,
        })

        expect(verifiedParRequest.dpop?.jwkThumbprint).toEqual(
          await calculateJwkThumbprint({
            hashAlgorithm: HashAlgorithm.Sha256,
            hashCallback: callbacks.hash,
            jwk: dpopJwkPublic,
          })
        )

        expect(verifiedParRequest.clientAttestation).toEqual({
          clientAttestation: {
            header: {
              alg: 'ES256',
              typ: 'oauth-client-attestation+jwt',
              jwk: walletProviderJwkPublic,
            },
            payload: {
              iss: 'https://wallet-provider.com',
              iat: expect.any(Number),
              exp: expect.any(Number),
              cnf: {
                jwk: walletConfirmationJwkPublic,
              },
              sub: 'wallet',
              wallet_name: 'Wallet',
              wallet_link: 'https://wallet-provider.com/wallet',
            },
            signer: {
              alg: 'ES256',
              method: 'jwk',
              publicJwk: walletProviderJwkPublic,
            },
          },
          clientAttestationPop: {
            header: {
              alg: 'ES256',
              typ: 'oauth-client-attestation-pop+jwt',
            },
            payload: {
              iss: 'wallet',
              aud: 'https://oauth2-auth-server.com',
              iat: expect.any(Number),
              exp: expect.any(Number),
              jti: expect.any(String),
            },
            signer: {
              alg: 'ES256',
              method: 'jwk',
              publicJwk: walletConfirmationJwkPublic,
            },
          },
        })

        expect(authorizationRequest).toEqual({
          issuer_state: 'something',
          resource: credentialIssuerMetadata.credential_issuer,
          response_type: 'code',
          client_id: 'wallet',
          redirect_uri: 'https://redirect.com',
          scope: 'PidSdJwt',
          code_challenge: expect.any(String),
          code_challenge_method: 'S256',
        })

        return Response.json({
          expires_in: 500,
          request_uri: `${authorizationServerMetadata.authorization_endpoint}?request_uri=${encodeURI('urn:something')}`,
        })
      }),
      http.post(authorizationServerMetadata.token_endpoint, async ({ request }) => {
        const accessTokenRequest = parseXwwwFormUrlEncoded(await request.text())
        expect(accessTokenRequest).toEqual({
          code: 'some-authorization-code',
          redirect_uri: 'https://redirect-uri.com',
          code_verifier: expect.any(String),
          grant_type: 'authorization_code',
          resource: credentialIssuerMetadata.credential_issuer,
        })

        const parsedAccessTokenRequest = authorizationServer.parseAccessTokenRequest({
          accessTokenRequest,
          request: {
            headers: request.headers,
            method: request.method as HttpMethod,
            url: request.url,
          },
        })
        expect(parsedAccessTokenRequest).toEqual({
          accessTokenRequest: {
            code: 'some-authorization-code',
            redirect_uri: 'https://redirect-uri.com',
            code_verifier: expect.any(String),
            grant_type: 'authorization_code',
            resource: createdCredentialOffer.credentialOfferObject.credential_issuer,
          },
          grant: {
            grantType: 'authorization_code',
            code: 'some-authorization-code',
          },
          dpopJwt: expect.any(String),
          clientAttestation: {
            clientAttestationJwt: expect.any(String),
            clientAttestationPopJwt: expect.any(String),
          },
          pkceCodeVerifier: expect.any(String),
        })

        // TODO:
        // - verify dpop matches with dpop from request
        //  - add expectedJwkThumprint
        // - verify client attestation matches with client attestation from auth request
        //   - is this needed? if so we can match the jwk thumbprint uri?
        //   - add client attestation to the verify access token request method
        // - verify dpop and wallet attestation key matches?
        //   - do we add a parameter to require this?

        if (parsedAccessTokenRequest.grant.grantType !== authorizationCodeGrantIdentifier) {
          return HttpResponse.json({
            error: 'invalid_grant',
            error_description: 'grant_type not supported',
          })
        }

        const { dpop } = await authorizationServer.verifyAuthorizationCodeAccessTokenRequest({
          grant: parsedAccessTokenRequest.grant,
          accessTokenRequest: parsedAccessTokenRequest.accessTokenRequest,
          pkce: {
            codeChallenge: encodeToBase64Url(
              callbacks.hash(decodeUtf8String('some-code-verifier'), HashAlgorithm.Sha256)
            ),
            codeChallengeMethod: PkceCodeChallengeMethod.S256,
            codeVerifier: parsedAccessTokenRequest.pkceCodeVerifier,
          },
          expectedCode: 'some-authorization-code',
          request: {
            method: request.method as HttpMethod,
            headers: request.headers,
            url: request.url,
          },
          dpop: {
            required: true,
            jwt: parsedAccessTokenRequest.dpopJwt,
            expectedJwkThumbprint: await calculateJwkThumbprint({
              hashAlgorithm: HashAlgorithm.Sha256,
              hashCallback: callbacks.hash,
              jwk: dpopJwk as Jwk,
            }),
          },
        })

        const accessTokenResponse = await authorizationServer.createAccessTokenResponse({
          audience: credentialIssuerMetadata.credential_issuer,
          signer: {
            method: 'jwk',
            alg: 'ES256',
            publicJwk: accessTokenJwkPublic,
          },
          subject: 'some-authorization-code',
          expiresInSeconds: 300,
          authorizationServer: authorizationServerMetadata.issuer,
          cNonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          cNonceExpiresIn: 100,
          clientId: 'wallet', // must be same as the client attestation
          dpopJwk: dpop?.jwk,
          scope: extractScopesForCredentialConfigurationIds({
            issuerMetadata,
            credentialConfigurationIds: createdCredentialOffer.credentialOfferObject.credential_configuration_ids,
            throwOnConfigurationWithoutScope: true,
          })?.join(' '),
        })
        return HttpResponse.json(accessTokenResponse)
      }),
      http.post(credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        const { dpopJwk, tokenPayload } = await resourceServer.verifyResourceRequest({
          authorizationServers: issuerMetadata.authorizationServers,
          request: {
            url: request.url,
            method: request.method as HttpMethod,
            headers: request.headers,
          },
          resourceServer: credentialIssuerMetadata.credential_issuer,
          allowedAuthenticationSchemes: [SupportedAuthenticationScheme.DPoP],
        })

        expect(dpopJwk).toEqual(dpopJwkPublic)
        expect(tokenPayload).toEqual({
          iss: authorizationServerMetadata.issuer,
          aud: credentialIssuerMetadata.credential_issuer,
          iat: expect.any(Number),
          exp: expect.any(Number),
          jti: expect.any(String),
          cnf: {
            jkt: await calculateJwkThumbprint({
              hashAlgorithm: HashAlgorithm.Sha256,
              hashCallback: callbacks.hash,
              jwk: dpopJwk as Jwk,
            }),
          },
          client_id: 'wallet',
          sub: 'some-authorization-code',
          scope: 'PidSdJwt',
        })

        const credentialRequest = await request.json()
        expect(credentialRequest).toEqual({
          format: 'vc+sd-jwt',
          vct: credentialConfigurationsSupported.pidSdJwt.vct,
          proof: {
            proof_type: 'jwt',
            jwt: expect.any(String),
          },
        })

        const parsedCredentialRequest = issuer.parseCredentialRequest({
          issuerMetadata: {
            authorizationServers: [],
            credentialIssuer: credentialIssuerMetadata,
            originalDraftVersion: Openid4vciDraftVersion.Draft14,
          },
          credentialRequest: credentialRequest as Record<string, unknown>,
        })

        if (!parsedCredentialRequest.proofs?.jwt) {
          throw new Error('Missing required jwt proofs')
        }

        const verifiedProof = await issuer.verifyCredentialRequestJwtProof({
          expectedNonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          issuerMetadata,
          jwt: parsedCredentialRequest.proofs.jwt[0],
        })
        expect(verifiedProof).toEqual({
          header: {
            alg: 'ES256',
            typ: 'openid4vci-proof+jwt',
            jwk: credentialRequestProofJwkPublic,
          },
          payload: {
            aud: credentialIssuerMetadata.credential_issuer,
            iat: expect.any(Number),
            nonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
          },
          signer: {
            alg: 'ES256',
            method: 'jwk',
            publicJwk: credentialRequestProofJwkPublic,
          },
        })

        expect(parsedCredentialRequest).toEqual({
          format: { format: 'vc+sd-jwt', vct: credentialConfigurationsSupported.pidSdJwt.vct },
          credentialRequest: {
            proof: {
              proof_type: 'jwt',
              jwt: expect.any(String),
            },
            format: 'vc+sd-jwt',
            vct: credentialConfigurationsSupported.pidSdJwt.vct,
          },
          proofs: {
            jwt: [expect.any(String)],
          },
        })

        const credentialResponse = issuer.createCredentialResponse({
          credential: 'some-credential',
          cNonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
          cNonceExpiresInSeconds: 500,
          notificationId: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
          credentialRequest: parsedCredentialRequest,
        })

        return HttpResponse.json(credentialResponse)
      })
    )

    // Overwrite for the mock
    callbacks.fetch = fetch

    const resolvedCredentialOffer = await client.resolveCredentialOffer(createdCredentialOffer.credentialOffer)
    expect(resolvedCredentialOffer).toStrictEqual(createdCredentialOffer.credentialOfferObject)

    const resolvedIssuerMetadata = await client.resolveIssuerMetadata(resolvedCredentialOffer.credential_issuer)
    expect(resolvedIssuerMetadata.credentialIssuer.credential_issuer).toStrictEqual(
      credentialIssuerMetadata.credential_issuer
    )

    const isDpopSupported = oauth2Client.isDpopSupported({
      authorizationServerMetadata,
    })
    expect(isDpopSupported).toEqual({
      supported: true,
      dpopSigningAlgValuesSupported: ['ES256'],
    })

    const {
      authorizationRequestUrl,
      pkce,
      dpop: dpopRequest,
    } = await client.createAuthorizationRequestUrlFromOffer({
      // TODO: how to deal with client here:
      // - add client authentication, can be none, clientAttestation, etc..
      // - extract client_id from client attestation?
      // - ...?
      clientId: 'wallet',
      credentialOffer: resolvedCredentialOffer,
      issuerMetadata,
      scope: extractScopesForCredentialConfigurationIds({
        credentialConfigurationIds: resolvedCredentialOffer.credential_configuration_ids,
        issuerMetadata,
        throwOnConfigurationWithoutScope: true,
      })?.join(' '),
      redirectUri: 'https://redirect.com',
      pkceCodeVerifier: 'some-code-verifier',
      // TODO: method to check if client attesattion is supported
      clientAttestation: {
        jwt: walletAttestation,
      },
      dpop: isDpopSupported.supported
        ? {
            signer: {
              method: 'jwk',
              alg: 'ES256',
              publicJwk: dpopJwkPublic,
            },
          }
        : undefined,
    })
    expect(pkce).toStrictEqual({
      codeChallenge: encodeToBase64Url(
        callbacks.hash(decodeUtf8String(pkce?.codeVerifier as string), HashAlgorithm.Sha256)
      ),
      codeChallengeMethod: 'S256',
      codeVerifier: expect.any(String),
    })
    expect(dpopRequest).toEqual({
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopJwkPublic,
      },
    })
    expect(authorizationRequestUrl).toStrictEqual(
      'https://oauth2-auth-server.com/authorize?request_uri=https%3A%2F%2Foauth2-auth-server.com%2Fauthorize%3Frequest_uri%3Durn%3Asomething&client_id=wallet'
    )

    const {
      accessTokenResponse,
      authorizationServer: authorizationServerIdentifier,
      dpop,
    } = await client.retrieveAuthorizationCodeAccessTokenFromOffer({
      credentialOffer: resolvedCredentialOffer,
      issuerMetadata,
      authorizationCode: 'some-authorization-code',
      pkceCodeVerifier: pkce?.codeVerifier,
      redirectUri: 'https://redirect-uri.com',
      // TODO: how to select the alg
      dpop: isDpopSupported.supported
        ? {
            signer: {
              alg: 'ES256',
              method: 'jwk',
              publicJwk: dpopJwkPublic,
            },
          }
        : undefined,
      clientAttestation: {
        jwt: walletAttestation,
      },
    })
    expect(accessTokenResponse).toStrictEqual({
      access_token: expect.any(String),
      c_nonce: 'cd59b02c-c199-4a31-903a-920a2830d2a4',
      c_nonce_expires_in: 100,
      expires_in: 300,
      token_type: 'DPoP',
    })
    expect(authorizationServerIdentifier).toStrictEqual(authorizationServerMetadata.issuer)

    const { jwt } = await client.createCredentialRequestJwtProof({
      credentialConfigurationId: resolvedCredentialOffer.credential_configuration_ids[0],
      issuerMetadata,
      // TODO: how to determine supported signer?
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      nonce: accessTokenResponse.c_nonce,
    })

    const credentialResponse = await client.retrieveCredentials({
      issuerMetadata,
      accessToken: accessTokenResponse.access_token,
      credentialConfigurationId: resolvedCredentialOffer.credential_configuration_ids[0],
      dpop,
      proof: {
        proof_type: 'jwt',
        jwt,
      },
    })
    expect(credentialResponse.credentialResponse).toEqual({
      c_nonce: 'd9457e7c-4cf7-461c-a8d0-94221ba865e7',
      c_nonce_expires_in: 500,
      credential: 'some-credential',
      notification_id: '3b926f09-d603-4e8b-a75d-eaa8965f0fe3',
      format: 'vc+sd-jwt',
    })
  })
})
