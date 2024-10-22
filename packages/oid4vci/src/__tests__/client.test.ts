import crypto from 'node:crypto'
import * as jose from 'jose'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { describe, expect, test } from 'vitest'
import { Oid4vciClient } from '../client'
import { paradym } from './__fixtures__/paradym'

describe('Oid4vciClient', () => {
  test('receive a credential from Paradym', async () => {
    const server = setupServer(
      http.get(paradym.credentialOfferUri.replace('?raw=true', ''), () =>
        HttpResponse.json(paradym.credentialOfferObject)
      ),
      http.get(`${paradym.credentialOfferObject.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.json(paradym.credentialIssuerMetadata)
      ),
      http.get(`${paradym.credentialOfferObject.credential_issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.post(paradym.credentialIssuerMetadata.token_endpoint, async ({ request }) => {
        expect(await request.text()).toEqual(
          'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=1130293840889780123292078'
        )
        return HttpResponse.json(paradym.accessTokenResponse)
      }),
      http.post(paradym.credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        expect(await request.json()).toEqual({
          format: 'vc+sd-jwt',
          vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
          proof: {
            proof_type: 'jwt',
            jwt: expect.any(String),
          },
        })
        return HttpResponse.json(paradym.credentialResponse)
      })
    )
    server.listen()

    const client = new Oid4vciClient({
      hashCallback: (data, alg) => crypto.createHash(alg).update(data).digest(),
      fetch,
    })

    const credentialOffer = await client.resolveCredentialOffer(paradym.credentialOffer)
    expect(credentialOffer).toStrictEqual(paradym.credentialOfferObject)

    const issuerMetadata = await client.resolveIssuerMetadata(credentialOffer.credential_issuer)
    expect(issuerMetadata.credentialIssuer).toStrictEqual(paradym.credentialIssuerMetadata)

    const { accessTokenResponse, authorizationServer } = await client.retrievePreAuthorizedCodeAccessToken({
      credentialOffer,
      issuerMetadata,
    })
    expect(accessTokenResponse).toStrictEqual(paradym.accessTokenResponse)
    expect(authorizationServer).toStrictEqual(paradym.credentialIssuerMetadata.credential_issuer)

    const { d, ...publicKeyJwk } = paradym.holderPrivateKeyJwk
    const encodedJwk = Buffer.from(JSON.stringify(publicKeyJwk)).toString('base64url')
    const didUrl = `did:jwk:${encodedJwk}#0`

    const jwtInput = client.createCredentialRequestJwtProof({
      alg: 'ES256',
      issuerMetadata,
      signer: {
        method: 'did',
        didUrl,
      },
      issuedAt: new Date('2024-10-10'),
      credentialConfigurationId: credentialOffer.credential_configuration_ids[0],
      nonce: accessTokenResponse.c_nonce,
    })
    expect(jwtInput).toStrictEqual({
      header: {
        alg: 'ES256',
        kid: 'did:jwk:eyJrdHkiOiJFQyIsIngiOiJBRVhwSHkxMEdodFdobFZQTm1yRnNieXRfd0RzUV83cTNkak5ucmh6al80IiwieSI6IkRHVEFDT0FBblFUZXBhRDQwZ3lHOVpsLW9EaE9sdjNVQmxUdHhJZXI1ZW8iLCJjcnYiOiJQLTI1NiJ9#0',
        typ: 'openid4vci-proof+jwt',
      },
      payload: {
        aud: 'https://agent.paradym.id/oid4vci/9b6df5bc-5965-4aec-a39a-03cb3b2786b5',
        iat: 1728518400,
        iss: undefined,
        nonce: '463253917094869172078310',
      },
    })

    const josePrivateKey = await jose.importJWK(paradym.holderPrivateKeyJwk, jwtInput.header.alg)
    const jwt = await new jose.SignJWT(jwtInput.payload).setProtectedHeader(jwtInput.header).sign(josePrivateKey)

    const { credentialResponse } = await client.retrieveCredentials({
      accessToken: accessTokenResponse.access_token,
      credentialConfigurationId: credentialOffer.credential_configuration_ids[0],
      issuerMetadata,
      proof: {
        proof_type: 'jwt',
        jwt,
      },
    })
    expect(credentialResponse).toStrictEqual(paradym.credentialResponse)
  })
})
