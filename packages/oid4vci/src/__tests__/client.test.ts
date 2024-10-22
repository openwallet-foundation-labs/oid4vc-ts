import crypto from 'node:crypto'
import * as jose from 'jose'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { Oid4vciClient } from '../client'
import { paradymDraft11, paradymDraft13 } from './__fixtures__/paradym'
import { preAuthorizedCodeGrantIdentifier } from '../credential-offer/v-credential-offer'

const server = setupServer()

describe('Oid4vciClient', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('receive a credential from Paradym using draft 13', async () => {
    server.resetHandlers(
      http.get(paradymDraft13.credentialOfferUri.replace('?raw=true', ''), () =>
        HttpResponse.json(paradymDraft13.credentialOfferObject)
      ),
      http.get(`${paradymDraft13.credentialOfferObject.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.json(paradymDraft13.credentialIssuerMetadata)
      ),
      http.get(`${paradymDraft13.credentialOfferObject.credential_issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.post(paradymDraft13.credentialIssuerMetadata.token_endpoint, async ({ request }) => {
        expect(await request.text()).toEqual(
          'pre-authorized_code=1130293840889780123292078&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code'
        )
        return HttpResponse.json(paradymDraft13.accessTokenResponse)
      }),
      http.post(paradymDraft13.credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        expect(await request.json()).toEqual({
          format: 'vc+sd-jwt',
          vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
          proof: {
            proof_type: 'jwt',
            jwt: expect.any(String),
          },
        })
        return HttpResponse.json(paradymDraft13.credentialResponse)
      })
    )

    const client = new Oid4vciClient({
      hashCallback: (data, alg) => crypto.createHash(alg).update(data).digest(),
      fetch,
    })

    const credentialOffer = await client.resolveCredentialOffer(paradymDraft13.credentialOffer)
    expect(credentialOffer).toStrictEqual(paradymDraft13.credentialOfferObject)

    const issuerMetadata = await client.resolveIssuerMetadata(credentialOffer.credential_issuer)
    expect(issuerMetadata.credentialIssuer).toStrictEqual(paradymDraft13.credentialIssuerMetadata)

    const { accessTokenResponse, authorizationServer } = await client.retrievePreAuthorizedCodeAccessToken({
      credentialOffer,
      issuerMetadata,
    })
    expect(accessTokenResponse).toStrictEqual(paradymDraft13.accessTokenResponse)
    expect(authorizationServer).toStrictEqual(paradymDraft13.credentialIssuerMetadata.credential_issuer)

    const { d, ...publicKeyJwk } = paradymDraft13.holderPrivateKeyJwk
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
        aud: 'https://agent.paradym.id/oid4vci/draft-13-issuer',
        iat: 1728518400,
        iss: undefined,
        nonce: '463253917094869172078310',
      },
    })

    const josePrivateKey = await jose.importJWK(paradymDraft13.holderPrivateKeyJwk, jwtInput.header.alg)
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
    expect(credentialResponse).toStrictEqual(paradymDraft13.credentialResponse)
  })

  test('receive a credential from Paradym using draft 11', async () => {
    server.resetHandlers(
      http.get(paradymDraft11.credentialOfferUri.replace('?raw=true', ''), () =>
        HttpResponse.json(paradymDraft11.credentialOfferObject)
      ),
      http.get(`${paradymDraft11.credentialOfferObject.credential_issuer}/.well-known/openid-credential-issuer`, () =>
        HttpResponse.json(paradymDraft11.credentialIssuerMetadata)
      ),
      http.get(`${paradymDraft11.credentialOfferObject.credential_issuer}/.well-known/oauth-authorization-server`, () =>
        HttpResponse.text(undefined, { status: 404 })
      ),
      http.post(paradymDraft11.credentialIssuerMetadata.token_endpoint, async ({ request }) => {
        expect(await request.text()).toEqual(
          'pre-authorized_code=1130293840889780123292078&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&user_pin=some-tx-code'
        )
        return HttpResponse.json(paradymDraft11.accessTokenResponse)
      }),
      http.post(paradymDraft11.credentialIssuerMetadata.credential_endpoint, async ({ request }) => {
        expect(await request.json()).toEqual({
          format: 'vc+sd-jwt',
          vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
          proof: {
            proof_type: 'jwt',
            jwt: expect.any(String),
          },
        })
        return HttpResponse.json(paradymDraft11.credentialResponse)
      })
    )

    const client = new Oid4vciClient({
      hashCallback: (data, alg) => crypto.createHash(alg).update(data).digest(),
      fetch,
    })

    const credentialOffer = await client.resolveCredentialOffer(paradymDraft11.credentialOffer)
    expect(credentialOffer).toStrictEqual({
      ...paradymDraft13.credentialOfferObject,
      credential_issuer: 'https://agent.paradym.id/oid4vci/draft-11-issuer',
      grants: {
        ...paradymDraft13.credentialOfferObject.grants,
        [preAuthorizedCodeGrantIdentifier]: {
          'pre-authorized_code':
            paradymDraft13.credentialOfferObject.grants[preAuthorizedCodeGrantIdentifier]['pre-authorized_code'],
          tx_code: {
            input_mode: 'text',
          },
        },
      },
    })

    const issuerMetadata = await client.resolveIssuerMetadata(credentialOffer.credential_issuer)
    expect(issuerMetadata.credentialIssuer).toStrictEqual({
      credential_issuer: 'https://agent.paradym.id/oid4vci/draft-11-issuer',
      credential_endpoint: 'https://agent.paradym.id/oid4vci/draft-11-issuer/credential',
      display: [{ name: 'Animo', logo: { alt_text: 'Logo of Animo Solutions', url: 'https://github.com/animo.png' } }],
      credential_configurations_supported: {
        clv2gbawu000tfkrk5l067h1h: {
          format: 'vc+sd-jwt',
          cryptographic_binding_methods_supported: ['did:key', 'did:jwk', 'did:web'],
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          display: [
            {
              name: 'Paradym Contributor',
              description: 'Contributed to the Paradym Release',
              background_color: '#5535ed',
              text_color: '#ffffff',
            },
          ],
          vct: 'https://metadata.paradym.id/types/iuoQGyxlww-ParadymContributor',
        },
        clvi9a5od00127pap4obzoeuf: {
          format: 'vc+sd-jwt',
          cryptographic_binding_methods_supported: ['did:key', 'did:jwk', 'did:web'],
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          display: [
            {
              name: 'Employee Badge',
              description: 'Credential for employee badge',
              background_color: '#000000',
              background_image: { uri: 'https://github.com/animo.png' },
              text_color: '#ffffff',
            },
          ],
          vct: 'https://metadata.paradym.id/types/6fTEgFULv2-EmployeeBadge',
        },
        clx4z0auo00a6f0sibkutdqor: {
          format: 'vc+sd-jwt',
          cryptographic_binding_methods_supported: ['did:key', 'did:jwk', 'did:web'],
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          display: [{ name: 'Direct issuance revocation', background_color: '#000000', text_color: '#ffffff' }],
          vct: 'https://metadata.paradym.id/types/ULaVABcapZ-Heyo',
        },
      },
      token_endpoint: 'https://agent.paradym.id/oid4vci/draft-11-issuer/token',
    })

    const { accessTokenResponse, authorizationServer } = await client.retrievePreAuthorizedCodeAccessToken({
      credentialOffer,
      issuerMetadata,
      txCode: 'some-tx-code',
    })
    expect(accessTokenResponse).toStrictEqual(paradymDraft11.accessTokenResponse)
    expect(authorizationServer).toStrictEqual(paradymDraft11.credentialIssuerMetadata.credential_issuer)

    const { d, ...publicKeyJwk } = paradymDraft11.holderPrivateKeyJwk
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
        aud: 'https://agent.paradym.id/oid4vci/draft-11-issuer',
        iat: 1728518400,
        iss: undefined,
        nonce: '463253917094869172078310',
      },
    })

    const josePrivateKey = await jose.importJWK(paradymDraft11.holderPrivateKeyJwk, jwtInput.header.alg)
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

    expect(credentialResponse).toStrictEqual(paradymDraft11.credentialResponse)
  })
})
