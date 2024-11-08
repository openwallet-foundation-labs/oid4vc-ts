import { preAuthorizedCodeGrantIdentifier } from '@animo-id/oauth2'
import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../oauth2/tests/util'
import { Oid4vciIssuer } from '../Oid4vciIssuer'
import { parseCredentialRequest } from '../credential-request/parse-credential-request'
import { createCredentialRequestJwtProof } from '../formats/proof-type/jwt/jwt-proof-type'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import { Oid4vciDraftVersion } from '../version'

const credentialRequestProofJwk = {
  kty: 'EC',
  d: 'ihMFBAANWoQDlKa-heCamTFADIUUS3H9vv7ednax498',
  crv: 'P-256',
  x: 'So52pS_IAc-AyzdX8LMBMxx9Zm2sPPOTMvXDrvZF53I',
  y: 'LZ2D24wpGdrM4Ex71SU9uFobvHTLmwXza4uhFp9Bpg8',
}
const { d, ...credentialRequestProofJwkPublic } = credentialRequestProofJwk

describe('Oid4vciIssuer', () => {
  test('create issuer metadata, create a credential offer, parse a credential request, create a credential response', async () => {
    const issuer = new Oid4vciIssuer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const credentialIssuerMetadata = issuer.createCredentialIssuerMetadata({
      credential_issuer: 'https://credential-issuer.com',
      credential_configurations_supported: {
        pidSdJwt: {
          format: 'vc+sd-jwt',
          vct: 'https://sd-jwt.com',
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
          credential_signing_alg_values_supported: ['ES256'],
          cryptographic_binding_methods_supported: ['jwk'],
          scope: 'PidSdJwt',
          display: [
            {
              name: 'PID SD JWT',
              background_color: '#FFFFFF',
              background_image: {
                uri: 'https://background-image.com',
              },
              description: 'PID SD JWT Credential',
              locale: 'en-US',
              logo: {
                uri: 'https://logo.com/logo.png',
                alt_text: 'logo of logo',
              },
              text_color: '#GGGGGG',
            },
          ],
        },
      },
      credential_endpoint: 'https://credential-issuer.com/credential',
      authorization_servers: ['https://one.com'],
      batch_credential_issuance: {
        batch_size: 10,
      },
      display: [
        {
          name: 'Oid4vciIssuer',
          locale: 'nl-NL',
          logo: {
            alt_text: 'some-log',
            uri: 'https://some-logo.com',
          },
        },
      ],
    })

    const issuerMetadata = {
      credentialIssuer: credentialIssuerMetadata,
      authorizationServers: [
        {
          issuer: 'https://one.com',
          token_endpoint: 'https://one.com/token',
        },
      ],
      originalDraftVersion: Oid4vciDraftVersion.Draft11,
    } as const satisfies IssuerMetadataResult

    const credentialOffer = await issuer.createCredentialOffer({
      credentialConfigurationIds: ['pidSdJwt'],
      grants: {
        [preAuthorizedCodeGrantIdentifier]: {
          'pre-authorized_code': 'qbRsnksAVad5J33Tw231MQDf5nvyiR-xsnvWXfo35NI',
          tx_code: {},
        },
        authorization_code: {},
      },
      issuerMetadata,
    })

    expect(credentialOffer).toStrictEqual({
      credentialOffer:
        'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.com%22%2C%22credential_configuration_ids%22%3A%5B%22pidSdJwt%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22qbRsnksAVad5J33Tw231MQDf5nvyiR-xsnvWXfo35NI%22%2C%22tx_code%22%3A%7B%7D%2C%22user_pin_required%22%3Atrue%7D%7D%2C%22credentials%22%3A%5B%22pidSdJwt%22%5D%7D',
      credentialOfferObject: {
        credential_configuration_ids: ['pidSdJwt'],
        credentials: ['pidSdJwt'],
        credential_issuer: 'https://credential-issuer.com',
        grants: {
          authorization_code: {},
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'qbRsnksAVad5J33Tw231MQDf5nvyiR-xsnvWXfo35NI',
            user_pin_required: true,
            tx_code: {},
          },
        },
      },
    })

    const credentialRequestJwt = await createCredentialRequestJwtProof({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([credentialRequestProofJwk]),
      },
      credentialIssuer: credentialIssuerMetadata.credential_issuer,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      nonce: 'some-nonce',
    })

    const parsedCredentialRequest = parseCredentialRequest({
      credentialRequest: {
        format: 'vc+sd-jwt',
        vct: 'https://sd-jwt.com',
        proof: {
          proof_type: 'jwt',
          jwt: credentialRequestJwt,
        },
      },
    })

    expect(parsedCredentialRequest).toEqual({
      credentialRequest: {
        format: 'vc+sd-jwt',
        proof: {
          jwt: credentialRequestJwt,
          proof_type: 'jwt',
        },
        vct: 'https://sd-jwt.com',
      },
      format: {
        format: 'vc+sd-jwt',
        vct: 'https://sd-jwt.com',
      },
      proofs: {
        jwt: [credentialRequestJwt],
      },
    })

    const verifyResult = await issuer.verifyCredentialRequestJwtProof({
      expectedNonce: 'some-nonce',
      issuerMetadata,
      jwt: parsedCredentialRequest.proofs?.jwt?.[0] as string,
    })
    expect(verifyResult).toEqual({
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: credentialRequestProofJwkPublic,
      },
      header: {
        alg: 'ES256',
        jwk: credentialRequestProofJwkPublic,
        typ: 'openid4vci-proof+jwt',
      },
      payload: {
        aud: 'https://credential-issuer.com',
        iat: expect.any(Number),
        nonce: 'some-nonce',
      },
    })

    const credentialResponse = issuer.createCredentialResponse({
      cNonce: 'some-new-nonce',
      cNonceExpiresInSeconds: 500,
      credential: 'the-credential',
      credentialRequest: parsedCredentialRequest,
    })

    expect(credentialResponse).toEqual({
      c_nonce: 'some-new-nonce',
      c_nonce_expires_in: 500,
      credential: 'the-credential',
      format: 'vc+sd-jwt',
    })
  })
})
