import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../oauth2/tests/util.mjs'
import { Openid4vciIssuer } from '../src/Openid4vciIssuer.js'

const fullV1Metadata = {
  credential_issuer: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41',
  credential_endpoint: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/credential',
  deferred_credential_endpoint:
    'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/deferred-credential',
  credential_configurations_supported: {
    'mobile-drivers-license-sd-jwt': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-sd-jwt',
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ['ES256'] },
      },
    },
    'mobile-drivers-license-sd-jwt-key-attestations': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-sd-jwt',
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
      },
    },
    'mobile-drivers-license-mdoc': {
      format: 'mso_mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ['ES256'] },
      },
    },
    'mobile-drivers-license-mdoc-key-attestations': {
      format: 'mso_mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-mdoc',
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
      },
    },
    'mobile-drivers-license-ldp-vc': {
      format: 'ldp_vc',
      cryptographic_binding_methods_supported: ['did:jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-ldp-vc',
      credential_definition: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
        type: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      },
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['EdDSA', 'Ed25519Signature2020'],
        },
      },
    },
    'mobile-drivers-license-ldp-vc-key-attestations': {
      format: 'ldp_vc',
      cryptographic_binding_methods_supported: ['did:jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'mobile-drivers-license-ldp-vc',
      credential_definition: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
        type: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      },
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'Drivers Licence',
            text_color: '#6F5C77',
            background_color: '#E6E2E7',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
          },
        ],
      },
      proof_types_supported: {},
    },
    'arf-pid-sd-jwt': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'arf-pid-sd-jwt',
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'PID (ARF)',
            text_color: '#2F3544',
            background_color: '#F1F2F0',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ['ES256'] },
      },
    },
    'arf-pid-sd-jwt-key-attestations': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'arf-pid-sd-jwt',
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'PID (ARF)',
            text_color: '#2F3544',
            background_color: '#F1F2F0',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
      },
    },
    'arf-pid-sd-jwt-urn-vct': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'arf-pid-sd-jwt-urn-vct',
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'PID (ARF, urn: vct)',
            text_color: '#2F3544',
            background_color: '#F1F2F0',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ['ES256'] },
      },
    },
    'arf-pid-sd-jwt-urn-vct-key-attestations': {
      format: 'dc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      scope: 'arf-pid-sd-jwt-urn-vct',
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
      credential_metadata: {
        display: [
          {
            locale: 'en',
            name: 'PID (ARF, urn: vct)',
            text_color: '#2F3544',
            background_color: '#F1F2F0',
            background_image: {
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
          },
        ],
      },
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: {
            user_authentication: ['iso_18045_high'],
            key_storage: ['iso_18045_high'],
          },
        },
      },
    },
  },
  display: [
    {
      name: 'Bundesdruckerei',
      logo: {
        url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/issuer.png',
        uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/issuer.png',
      },
    },
  ],
  nonce_endpoint: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/nonce',
  batch_credential_issuance: { batch_size: 10 },
}

const transformedDraft11Metadata = {
  credential_issuer: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41',
  credential_endpoint: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/credential',
  deferred_credential_endpoint:
    'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/deferred-credential',
  nonce_endpoint: 'https://e949ea0fd8ff.ngrok-free.app/oid4vci/188e2459-6da8-4431-9062-2fcdac274f41/nonce',
  batch_credential_issuance: { batch_size: 10 },
  display: [
    {
      name: 'Bundesdruckerei',
      logo: {
        uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/issuer.png',
        url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/issuer.png',
      },
    },
  ],
  credential_configurations_supported: {
    'mobile-drivers-license-sd-jwt': {
      format: 'dc+sd-jwt',
      scope: 'mobile-drivers-license-sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'mobile-drivers-license-sd-jwt-key-attestations': {
      format: 'dc+sd-jwt',
      scope: 'mobile-drivers-license-sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
      },
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'mobile-drivers-license-mdoc': {
      format: 'mso_mdoc',
      scope: 'mobile-drivers-license-mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'mobile-drivers-license-mdoc-key-attestations': {
      format: 'mso_mdoc',
      scope: 'mobile-drivers-license-mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
      },
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'mobile-drivers-license-ldp-vc': {
      format: 'ldp_vc',
      scope: 'mobile-drivers-license-ldp-vc',
      cryptographic_binding_methods_supported: ['did:jwk'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['EdDSA', 'Ed25519Signature2020'] } },
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      credential_definition: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
        type: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      },
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'mobile-drivers-license-ldp-vc-key-attestations': {
      format: 'ldp_vc',
      scope: 'mobile-drivers-license-ldp-vc',
      cryptographic_binding_methods_supported: ['did:jwk'],
      proof_types_supported: {},
      credential_metadata: {
        display: [
          {
            name: 'Drivers Licence',
            locale: 'en',
            background_color: '#E6E2E7',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            },
            text_color: '#6F5C77',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      credential_definition: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
        type: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      },
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png',
          },
        },
      ],
    },
    'arf-pid-sd-jwt': {
      format: 'dc+sd-jwt',
      scope: 'arf-pid-sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
      credential_metadata: {
        display: [
          {
            name: 'PID (ARF)',
            locale: 'en',
            background_color: '#F1F2F0',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
            text_color: '#2F3544',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
    },
    'arf-pid-sd-jwt-key-attestations': {
      format: 'dc+sd-jwt',
      scope: 'arf-pid-sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
      },
      credential_metadata: {
        display: [
          {
            name: 'PID (ARF)',
            locale: 'en',
            background_color: '#F1F2F0',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
            text_color: '#2F3544',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
    },
    'arf-pid-sd-jwt-urn-vct': {
      format: 'dc+sd-jwt',
      scope: 'arf-pid-sd-jwt-urn-vct',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
      credential_metadata: {
        display: [
          {
            name: 'PID (ARF, urn: vct)',
            locale: 'en',
            background_color: '#F1F2F0',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
            text_color: '#2F3544',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
    },
    'arf-pid-sd-jwt-urn-vct-key-attestations': {
      format: 'dc+sd-jwt',
      scope: 'arf-pid-sd-jwt-urn-vct',
      cryptographic_binding_methods_supported: ['jwk'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
        attestation: {
          proof_signing_alg_values_supported: ['ES256'],
          key_attestations_required: { key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'] },
        },
      },
      credential_metadata: {
        display: [
          {
            name: 'PID (ARF, urn: vct)',
            locale: 'en',
            background_color: '#F1F2F0',
            background_image: {
              uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
              url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            },
            text_color: '#2F3544',
          },
        ],
      },
      cryptographic_suites_supported: ['ES256'],
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          background_image: {
            url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
            uri: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png',
          },
        },
      ],
    },
  },
  credentials_supported: [
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
        },
      ],
      id: 'mobile-drivers-license-sd-jwt',
    },
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'https://example.eudi.ec.europa.eu/mdl/1',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
        },
      ],
      id: 'mobile-drivers-license-sd-jwt-key-attestations',
    },
    {
      format: 'mso_mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      cryptographic_suites_supported: ['ES256'],
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
        },
      ],
      id: 'mobile-drivers-license-mdoc',
    },
    {
      format: 'mso_mdoc',
      cryptographic_binding_methods_supported: ['cose_key'],
      cryptographic_suites_supported: ['ES256'],
      doctype: 'org.iso.18013.5.1.mDL',
      display: [
        {
          locale: 'en',
          name: 'Drivers Licence',
          text_color: '#6F5C77',
          background_color: '#E6E2E7',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
        },
      ],
      id: 'mobile-drivers-license-mdoc-key-attestations',
    },
    {
      format: 'ldp_vc',
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
      types: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      cryptographic_binding_methods_supported: ['did:jwk'],
      display: [
        {
          name: 'Drivers Licence',
          locale: 'en',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
          background_color: '#E6E2E7',
          text_color: '#6F5C77',
        },
      ],
      cryptographic_suites_supported: ['ES256'],
      id: 'mobile-drivers-license-ldp-vc',
    },
    {
      format: 'ldp_vc',
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vdl/v2'],
      types: ['VerifiableCredential', 'Iso18013DriversLicenseCredential'],
      cryptographic_binding_methods_supported: ['did:jwk'],
      display: [
        {
          name: 'Drivers Licence',
          locale: 'en',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/credential.png' },
          background_color: '#E6E2E7',
          text_color: '#6F5C77',
        },
      ],
      cryptographic_suites_supported: ['ES256'],
      id: 'mobile-drivers-license-ldp-vc-key-attestations',
    },
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png' },
        },
      ],
      id: 'arf-pid-sd-jwt',
    },
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'eu.europa.ec.eudi.pid.1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png' },
        },
      ],
      id: 'arf-pid-sd-jwt-key-attestations',
    },
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png' },
        },
      ],
      id: 'arf-pid-sd-jwt-urn-vct',
    },
    {
      format: 'vc+sd-jwt',
      cryptographic_binding_methods_supported: ['jwk'],
      cryptographic_suites_supported: ['ES256'],
      vct: 'urn:eu.europa.ec.eudi:pid:1',
      display: [
        {
          locale: 'en',
          name: 'PID (ARF, urn: vct)',
          text_color: '#2F3544',
          background_color: '#F1F2F0',
          logo: { url: 'https://e949ea0fd8ff.ngrok-free.app/assets/issuers/bdr/pid-credential.png' },
        },
      ],
      id: 'arf-pid-sd-jwt-urn-vct-key-attestations',
    },
  ],
}

describe('OpenID4VCI | Draft 11', () => {
  test('getCredentialIssuerMetadataDraft11 transforms v1 issuer metadata into draft 11 issuer metadata ', () => {
    const issuer = new Openid4vciIssuer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })
    expect(issuer.getCredentialIssuerMetadataDraft11(fullV1Metadata)).toEqual(transformedDraft11Metadata)
  })
})
