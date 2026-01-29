import { authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { callbacks } from '../../../../oauth2/tests/util.mjs'
import type { IssuerMetadataResult } from '../../metadata/fetch-issuer-metadata.js'
import { Openid4vciVersion } from '../../version.js'
import { createCredentialOffer } from '../credential-offer.js'

const issuerMetadata = {
  authorizationServers: [],
  credentialIssuer: {
    credential_issuer: 'https://agent.paradym.id/oid4vci/fcfd0e5d-69cf-4ab8-91b9-8ba2780fa052',
    token_endpoint: 'https://agent.paradym.id/oid4vci/fcfd0e5d-69cf-4ab8-91b9-8ba2780fa052/token',
    credential_endpoint: 'https://agent.paradym.id/oid4vci/fcfd0e5d-69cf-4ab8-91b9-8ba2780fa052/credential',
    credential_configurations_supported: {
      test: {
        format: 'vc+sd-jwt',
      },
    },
  },
  originalDraftVersion: Openid4vciVersion.Draft14,
  knownCredentialConfigurations: {},
} as const satisfies IssuerMetadataResult

describe('Credential Offer', () => {
  test('create credential offer', async () => {
    const { credentialOffer, credentialOfferObject } = await createCredentialOffer({
      credentialConfigurationIds: ['test'],
      grants: {
        [preAuthorizedCodeGrantIdentifier]: {
          tx_code: {
            input_mode: 'text',
          },
        },
        [authorizationCodeGrantIdentifier]: {
          issuer_state: '4705d207-8e27-473f-8fa9-65aa4f06c455',
        },
      },
      callbacks,
      issuerMetadata,
    })

    expect(credentialOfferObject).toEqual({
      credential_configuration_ids: ['test'],
      credential_issuer: 'https://agent.paradym.id/oid4vci/fcfd0e5d-69cf-4ab8-91b9-8ba2780fa052',
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': expect.any(String),
          tx_code: {
            input_mode: 'text',
          },
        },
        authorization_code: {
          issuer_state: '4705d207-8e27-473f-8fa9-65aa4f06c455',
        },
      },
    })

    expect(credentialOffer).toEqual(
      `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOfferObject))}`
    )
  })

  test('create credential offer with custom schema and uri', async () => {
    const { credentialOffer } = await createCredentialOffer({
      credentialConfigurationIds: ['test'],
      grants: {
        [preAuthorizedCodeGrantIdentifier]: {},
      },
      callbacks,
      issuerMetadata,
      credentialOfferScheme: 'https://paradym.id/invitation',
      credentialOfferUri:
        'https://paradym.id/invitation/197e8663-2046-4b8d-9090-8594a8b99d0b/offers/599dbc75-a6fb-45e7-9c22-2591f89effd7',
    })

    expect(credentialOffer).toEqual(
      `https://paradym.id/invitation?credential_offer_uri=${encodeURIComponent('https://paradym.id/invitation/197e8663-2046-4b8d-9090-8594a8b99d0b/offers/599dbc75-a6fb-45e7-9c22-2591f89effd7')}`
    )
  })

  test('create credential offer with authorization servers in offer', async () => {
    const { credentialOfferObject } = await createCredentialOffer({
      credentialConfigurationIds: ['test'],
      grants: {
        [preAuthorizedCodeGrantIdentifier]: {
          authorization_server: 'https://pre-auth-server.com',
        },
        [authorizationCodeGrantIdentifier]: {
          authorization_server: 'https://auth-server.com',
        },
      },
      callbacks,
      issuerMetadata: {
        ...issuerMetadata,
        credentialIssuer: {
          ...issuerMetadata.credentialIssuer,
          authorization_servers: ['https://pre-auth-server.com', 'https://auth-server.com'],
        },
      },
    })

    expect(credentialOfferObject).toEqual({
      credential_configuration_ids: ['test'],
      credential_issuer: 'https://agent.paradym.id/oid4vci/fcfd0e5d-69cf-4ab8-91b9-8ba2780fa052',
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': expect.any(String),
          authorization_server: 'https://pre-auth-server.com',
        },
        authorization_code: {
          authorization_server: 'https://auth-server.com',
        },
      },
    })
  })

  test('throws error when issuer metadata does not contain the credential configuration id', async () => {
    await expect(
      createCredentialOffer({
        credentialConfigurationIds: ['testw'],
        grants: {},
        callbacks,
        issuerMetadata,
      })
    ).rejects.toThrow(
      "Credential configuration ids testw not found in the credential issuer metadata 'credential_configurations_supported'. Available ids are test."
    )
  })

  test('throws error when no authorization_server for grant but multiple authorization_servers in issuer metadata', async () => {
    await expect(
      createCredentialOffer({
        credentialConfigurationIds: ['test'],
        grants: {
          [authorizationCodeGrantIdentifier]: {},
        },
        callbacks,
        issuerMetadata: {
          ...issuerMetadata,
          credentialIssuer: {
            ...issuerMetadata.credentialIssuer,
            authorization_servers: ['https://one.com', 'https://two.com'],
          },
        },
      })
    ).rejects.toThrow(
      "Credential issuer metadata has 'authorization_server' with multiple entries, but the credential offer grant did not specify which authorization server to use."
    )
  })

  test('throws error when authorization_server for grant but no authorization_servers in issuer metadata', async () => {
    await expect(
      createCredentialOffer({
        credentialConfigurationIds: ['test'],
        grants: {
          [authorizationCodeGrantIdentifier]: {
            authorization_server: 'https://one.com',
          },
        },
        callbacks,
        issuerMetadata: {
          ...issuerMetadata,
          credentialIssuer: {
            ...issuerMetadata.credentialIssuer,
            // authorization_servers: ['https://one.com', 'https://two.com'],
          },
        },
      })
    ).rejects.toThrow(
      "Credential offer grant contains 'authorization_server' with value 'https://one.com' but credential issuer metadata does not have an 'authorization_servers' property to match the value against."
    )
  })

  test('throws error when authorization_server for grant but the value is not present in authorization_servers in issuer metadata', async () => {
    await expect(
      createCredentialOffer({
        credentialConfigurationIds: ['test'],
        grants: {
          [authorizationCodeGrantIdentifier]: {
            authorization_server: 'https://three.com',
          },
        },
        callbacks,
        issuerMetadata: {
          ...issuerMetadata,
          credentialIssuer: {
            ...issuerMetadata.credentialIssuer,
            authorization_servers: ['https://one.com', 'https://two.com'],
          },
        },
      })
    ).rejects.toThrow(
      "Credential offer grant contains 'authorization_server' with value 'https://three.com' but credential issuer metadata does not include this authorization server. Available 'authorization_server' values are https://one.com, https://two.com."
    )
  })
})
