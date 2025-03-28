import { preAuthorizedCodeGrantIdentifier } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { zCredentialOfferObject, zCredentialOfferObjectDraft11To14 } from '../z-credential-offer.js'

describe('Credential Offer', () => {
  test('parse draft 14 credential offer', () => {
    const parseResult = zCredentialOfferObject.safeParse({
      credential_issuer: 'https://issuer.com',
      grants: {
        authorization_code: {
          issuer_state: 'issuer_state',
          authoriztation_server: 'https://authorization.com',
          extra_params: 'also-transformed',
        },
        [preAuthorizedCodeGrantIdentifier]: {
          tx_code: {
            length: 8,
          },
          authoriztation_server: 'https://authorization.com',
          'pre-authorized_code': 'some-code',
        },
      },
      credential_configuration_ids: ['credential-1', 'credential-2'],
    })

    expect(parseResult).toStrictEqual({
      success: true,
      data: {
        credential_issuer: 'https://issuer.com',
        grants: {
          authorization_code: {
            issuer_state: 'issuer_state',
            authoriztation_server: 'https://authorization.com',
            extra_params: 'also-transformed',
          },
          [preAuthorizedCodeGrantIdentifier]: {
            tx_code: {
              length: 8,
            },
            authoriztation_server: 'https://authorization.com',
            'pre-authorized_code': 'some-code',
          },
        },
        credential_configuration_ids: ['credential-1', 'credential-2'],
      },
    })
  })

  test('parse draft 11 credential offer and transform into draft 14', () => {
    const parseResult = zCredentialOfferObject.safeParse({
      credential_issuer: 'https://issuer.com',
      grants: {
        authorization_code: {
          issuer_state: 'issuer_state',
          extra_params: 'also-transformed',
        },
        [preAuthorizedCodeGrantIdentifier]: {
          user_pin_required: true,
          'pre-authorized_code': 'some-code',
        },
      },
      credentials: ['credential-1', 'credential-2'],
    })

    expect(parseResult).toStrictEqual({
      data: {
        credential_configuration_ids: ['credential-1', 'credential-2'],
        credential_issuer: 'https://issuer.com',
        grants: {
          authorization_code: {
            extra_params: 'also-transformed',
            issuer_state: 'issuer_state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'some-code',
            tx_code: {
              input_mode: 'text',
            },
          },
        },
      },
      success: true,
    })
  })

  test('parse draft 11 credential offer with inline offer object and throw error', () => {
    const parseResult = zCredentialOfferObjectDraft11To14.safeParse({
      credential_issuer: 'https://issuer.com',
      grants: {},
      credentials: [
        {
          format: 'vc+sd-jwt',
        },
      ],
    })

    expect(parseResult.success).toBe(false)
    expect(parseResult.error?.errors).toMatchInlineSnapshot(`
      [
        {
          "code": "invalid_type",
          "expected": "string",
          "message": "Only string credential identifiers are supported for draft 11 credential offers",
          "path": [
            "credentials",
            0,
          ],
          "received": "object",
        },
      ]
    `)
  })
})
