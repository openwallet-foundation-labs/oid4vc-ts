import { preAuthorizedCodeGrantIdentifier } from '@openid4vc/oauth2'
import * as v from 'valibot'
import { describe, expect, test } from 'vitest'
import { vCredentialOfferObject, vCredentialOfferObjectDraft11To14 } from '../v-credential-offer'

describe('Credential Offer', () => {
  test('parse draft 14 credential offer', () => {
    const parseResult = v.safeParse(vCredentialOfferObject, {
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
      issues: undefined,
      output: {
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
      success: true,
      typed: true,
    })
  })

  test('parse draft 11 credential offer and transform into draft 14', () => {
    const parseResult = v.safeParse(vCredentialOfferObject, {
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
      issues: undefined,
      output: {
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
      typed: true,
    })
  })

  test('parse draft 11 credential offer with inline offer object and throw error', () => {
    const parseResult = v.safeParse(vCredentialOfferObjectDraft11To14, {
      credential_issuer: 'https://issuer.com',
      grants: {},
      credentials: [
        {
          format: 'vc+sd-jwt',
        },
      ],
    })

    expect(parseResult).toStrictEqual({
      issues: [
        {
          abortEarly: undefined,
          abortPipeEarly: undefined,
          expected: 'string',
          input: {
            format: 'vc+sd-jwt',
          },
          issues: undefined,
          kind: 'schema',
          lang: undefined,
          message: 'Invalid type: Expected string but received Object',
          path: [
            {
              input: {
                credential_issuer: 'https://issuer.com',
                credentials: [
                  {
                    format: 'vc+sd-jwt',
                  },
                ],
                grants: {},
              },
              key: 'credentials',
              origin: 'value',
              type: 'object',
              value: [
                {
                  format: 'vc+sd-jwt',
                },
              ],
            },
            {
              input: [
                {
                  format: 'vc+sd-jwt',
                },
              ],
              key: 0,
              origin: 'value',
              type: 'array',
              value: {
                format: 'vc+sd-jwt',
              },
            },
          ],
          received: 'Object',
          requirement: undefined,
          type: 'string',
        },
      ],
      output: {
        credential_issuer: 'https://issuer.com',
        credentials: [
          {
            format: 'vc+sd-jwt',
          },
        ],
        grants: {},
      },
      success: false,
      typed: false,
    })
  })
})
