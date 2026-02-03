import { describe, expect, test } from 'vitest'
import {
  claimsObjectToClaimsArray,
  credentialsSupportedToCredentialConfigurationsSupported,
} from '../credential-configurations'

describe('Credential Configurations', () => {
  test('credentials supported to credential configurations supported', () => {
    expect(
      credentialsSupportedToCredentialConfigurationsSupported([
        {
          id: 'd2662472-891c-413d-b3c6-e2f0109001c5',
          format: 'ldp_vc',
          '@context': [],
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did:key'],
          cryptographic_suites_supported: ['Ed25519Signature2018'],
          display: [
            {
              name: 'Example University Degree',
              description: 'JFF Plugfest 3 OpenBadge Credential',
              background_color: '#464c49',
              logo: {},
            },
          ],
        },
        {
          id: '613ecbbb-0a4c-4041-bb78-c64943139d5f',
          format: 'jwt_vc_json',
          types: ['VerifiableCredential', 'OpenBadgeCredential'],
          cryptographic_binding_methods_supported: ['did:key'],
          cryptographic_suites_supported: ['EdDSA'],
          display: [
            {
              name: 'Example University Degree',
              description: 'JFF Plugfest 3 OpenBadge Credential',
              background_color: '#464c49',
              logo: {},
            },
          ],
        },
        {
          id: '904afaa1-f319-4a12-9c3c-0a6081c3feb0',
          format: 'mso_mdoc',
          doctype: 'some-doc-type',
          cryptographic_binding_methods_supported: ['did:key'],
          cryptographic_suites_supported: ['EdDSA'],
          display: [
            {
              name: 'Passport',
              description: 'Passport of the Kingdom of Kākāpō',
              background_color: '#171717',
              logo: {},
            },
          ],
        },
        {
          id: 'c3db5513-ae2b-46e9-8a0d-fbfd0ce52b6a',
          format: 'vc+sd-jwt',
          vct: 'something',
          cryptographic_binding_methods_supported: ['did:key'],
          cryptographic_suites_supported: ['EdDSA'],
          display: [
            {
              name: 'Passport',
              description: 'Passport of the Kingdom of Kākāpō',
              background_color: '#171717',
              logo: { url: 'https://static.mattr.global/credential-assets/government-of-kakapo/web/logo.svg' },
            },
          ],
        },
      ])
    ).toEqual({
      'd2662472-891c-413d-b3c6-e2f0109001c5': {
        format: 'ldp_vc',
        credential_definition: {
          '@context': [],
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
        },
        cryptographic_binding_methods_supported: ['did:key'],
        credential_signing_alg_values_supported: ['Ed25519Signature2018'],
        credential_metadata: {
          display: [
            {
              name: 'Example University Degree',
              description: 'JFF Plugfest 3 OpenBadge Credential',
              background_color: '#464c49',
            },
          ],
        },
      },
      '613ecbbb-0a4c-4041-bb78-c64943139d5f': {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['VerifiableCredential', 'OpenBadgeCredential'],
        },
        cryptographic_binding_methods_supported: ['did:key'],
        credential_signing_alg_values_supported: ['EdDSA'],
        credential_metadata: {
          display: [
            {
              name: 'Example University Degree',
              description: 'JFF Plugfest 3 OpenBadge Credential',
              background_color: '#464c49',
            },
          ],
        },
      },
      '904afaa1-f319-4a12-9c3c-0a6081c3feb0': {
        format: 'mso_mdoc',
        doctype: 'some-doc-type',
        cryptographic_binding_methods_supported: ['did:key'],
        credential_signing_alg_values_supported: [-19],
        credential_metadata: {
          display: [
            {
              name: 'Passport',
              description: 'Passport of the Kingdom of Kākāpō',
              background_color: '#171717',
            },
          ],
        },
      },
      'c3db5513-ae2b-46e9-8a0d-fbfd0ce52b6a': {
        format: 'dc+sd-jwt',
        vct: 'something',
        cryptographic_binding_methods_supported: ['did:key'],
        credential_signing_alg_values_supported: ['EdDSA'],
        credential_metadata: {
          display: [
            {
              name: 'Passport',
              description: 'Passport of the Kingdom of Kākāpō',
              background_color: '#171717',
              logo: { uri: 'https://static.mattr.global/credential-assets/government-of-kakapo/web/logo.svg' },
            },
          ],
        },
      },
    })
  })

  test('credentials supported to credential configurations supported based on Credo', () => {
    expect(
      credentialsSupportedToCredentialConfigurationsSupported([
        {
          id: 'alpha-credential-1.0.0',
          format: 'vc+sd-jwt',
          vct: 'ALPHA_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Profile Information',
            },
            {
              locale: 'de',
              name: 'Profilinformationen',
            },
          ],
          claims: {
            givenName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Given name',
                },
                {
                  locale: 'de',
                  name: 'Vorname',
                },
              ],
              value_type: 'string',
            },
            familyName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Family name',
                },
                {
                  locale: 'de',
                  name: 'Nachname',
                },
              ],
              value_type: 'string',
            },
            birthDate: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Birth date',
                },
                {
                  locale: 'de',
                  name: 'Geburtsdatum',
                },
              ],
              value_type: 'string',
            },
            registrationId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Registration identifier',
                },
                {
                  locale: 'de',
                  name: 'Registrierungskennung',
                },
              ],
              value_type: 'string',
            },
            _fullRegistrationId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Complete registration identifier',
                },
                {
                  locale: 'de',
                  name: 'Vollständige Registrierungskennung',
                },
              ],
              value_type: 'string',
            },
            taxId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Tax identifier',
                },
                {
                  locale: 'de',
                  name: 'Steueridentifikator',
                },
              ],
              value_type: 'string',
            },
          },
        },
        {
          id: 'beta-entitlement-1.0.0',
          format: 'vc+sd-jwt',
          vct: 'BETA_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Continental Access Pass',
            },
            {
              locale: 'de',
              name: 'Kontinentaler Zugangspass',
            },
          ],
          claims: {
            fullName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Full name',
                },
                {
                  locale: 'de',
                  name: 'Vollständiger Name',
                },
              ],
              value_type: 'string',
            },
            additionalNames: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Additional names',
                },
                {
                  locale: 'de',
                  name: 'Zusätzliche Namen',
                },
              ],
              value_type: 'string',
            },
            birthDate: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Birth date',
                },
                {
                  locale: 'de',
                  name: 'Geburtsdatum',
                },
              ],
              value_type: 'string',
            },
            subjectId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Subject identifier',
                },
                {
                  locale: 'de',
                  name: 'Subjektkennung',
                },
              ],
              value_type: 'string',
            },
            passId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Pass identifier',
                },
                {
                  locale: 'de',
                  name: 'Pass-Kennung',
                },
              ],
              value_type: 'string',
            },
            expirationDate: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Expires on',
                },
                {
                  locale: 'de',
                  name: 'Gültig bis',
                },
              ],
              value_type: 'string',
            },
            orgId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Organization identifier',
                },
                {
                  locale: 'de',
                  name: 'Organisationskennung',
                },
              ],
              value_type: 'string',
            },
          },
        },
        {
          id: 'gamma-entitlement-1.1.0',
          format: 'vc+sd-jwt',
          vct: 'GAMMA_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Premium Access',
            },
            {
              locale: 'de',
              name: 'Premium-Zugang',
            },
          ],
          claims: {
            givenName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Given name',
                },
                {
                  locale: 'de',
                  name: 'Vorname',
                },
              ],
              value_type: 'string',
            },
            familyName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Family name',
                },
                {
                  locale: 'de',
                  name: 'Nachname',
                },
              ],
              value_type: 'string',
            },
            birthDate: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Birth date',
                },
                {
                  locale: 'de',
                  name: 'Geburtsdatum',
                },
              ],
              value_type: 'string',
            },
            category: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Category',
                },
                {
                  locale: 'de',
                  name: 'Kategorie',
                },
              ],
              value_type: 'string',
            },
            providerName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Provider name',
                },
                {
                  locale: 'de',
                  name: 'Anbietername',
                },
              ],
              value_type: 'string',
            },
            visibleAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Access identifier',
                },
                {
                  locale: 'de',
                  name: 'Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _internalAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Internal access identifier',
                },
                {
                  locale: 'de',
                  name: 'Interne Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _typeCode: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Type code',
                },
                {
                  locale: 'de',
                  name: 'Typcode',
                },
              ],
              value_type: 'string',
            },
            validUntil: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Valid until',
                },
                {
                  locale: 'de',
                  name: 'Gültig bis',
                },
              ],
              value_type: 'string',
            },
          },
        },
        {
          id: 'delta-entitlement-1.1.0',
          format: 'vc+sd-jwt',
          vct: 'DELTA_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Service Access',
            },
            {
              locale: 'de',
              name: 'Dienstzugang',
            },
          ],
          claims: {
            givenName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Given name',
                },
                {
                  locale: 'de',
                  name: 'Vorname',
                },
              ],
              value_type: 'string',
            },
            familyName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Family name',
                },
                {
                  locale: 'de',
                  name: 'Nachname',
                },
              ],
              value_type: 'string',
            },
            birthDate: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Birth date',
                },
                {
                  locale: 'de',
                  name: 'Geburtsdatum',
                },
              ],
              value_type: 'string',
            },
            category: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Category',
                },
                {
                  locale: 'de',
                  name: 'Kategorie',
                },
              ],
              value_type: 'string',
            },
            providerName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Provider name',
                },
                {
                  locale: 'de',
                  name: 'Anbietername',
                },
              ],
              value_type: 'string',
            },
            visibleAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Access identifier',
                },
                {
                  locale: 'de',
                  name: 'Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _internalAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Internal access identifier',
                },
                {
                  locale: 'de',
                  name: 'Interne Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _typeCode: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Type code',
                },
                {
                  locale: 'de',
                  name: 'Typcode',
                },
              ],
              value_type: 'string',
            },
            validUntil: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Valid until',
                },
                {
                  locale: 'de',
                  name: 'Gültig bis',
                },
              ],
              value_type: 'string',
            },
          },
        },
        {
          id: 'epsilon-entitlement-1.0.1',
          format: 'vc+sd-jwt',
          vct: 'EPSILON_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Extended Coverage Program',
            },
            {
              locale: 'de',
              name: 'Erweitertes Versorgungsprogramm',
            },
          ],
          claims: {
            givenName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Given name',
                },
                {
                  locale: 'de',
                  name: 'Vorname',
                },
              ],
              value_type: 'string',
            },
            familyName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Family name',
                },
                {
                  locale: 'de',
                  name: 'Nachname',
                },
              ],
              value_type: 'string',
            },
            birthDate: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Birth date',
                },
                {
                  locale: 'de',
                  name: 'Geburtsdatum',
                },
              ],
              value_type: 'string',
            },
            category: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Category',
                },
                {
                  locale: 'de',
                  name: 'Kategorie',
                },
              ],
              value_type: 'string',
            },
            providerName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Provider name',
                },
                {
                  locale: 'de',
                  name: 'Anbietername',
                },
              ],
              value_type: 'string',
            },
            visibleAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Access identifier',
                },
                {
                  locale: 'de',
                  name: 'Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _internalAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Internal access identifier',
                },
                {
                  locale: 'de',
                  name: 'Interne Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _typeCode: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Type code',
                },
                {
                  locale: 'de',
                  name: 'Typcode',
                },
              ],
              value_type: 'string',
            },
            validUntil: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Valid until',
                },
                {
                  locale: 'de',
                  name: 'Gültig bis',
                },
              ],
              value_type: 'string',
            },
            programCode: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Program code',
                },
                {
                  locale: 'de',
                  name: 'Programmcode',
                },
              ],
              value_type: 'string',
            },
          },
        },
        {
          id: 'zeta-entitlement-1.1.0',
          format: 'vc+sd-jwt',
          vct: 'ZETA_TYPE',
          display: [
            {
              locale: 'en',
              name: 'Cost Reduction Scheme',
            },
            {
              locale: 'de',
              name: 'Kostensenkungsprogramm',
            },
          ],
          claims: {
            givenName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Given name',
                },
                {
                  locale: 'de',
                  name: 'Vorname',
                },
              ],
              value_type: 'string',
            },
            familyName: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Family name',
                },
                {
                  locale: 'de',
                  name: 'Nachname',
                },
              ],
              value_type: 'string',
            },
            category: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Category',
                },
                {
                  locale: 'de',
                  name: 'Kategorie',
                },
              ],
              value_type: 'string',
            },
            visibleAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Access identifier',
                },
                {
                  locale: 'de',
                  name: 'Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _internalAccessId: {
              mandatory: true,
              display: [
                {
                  locale: 'en',
                  name: 'Internal access identifier',
                },
                {
                  locale: 'de',
                  name: 'Interne Zugangskennung',
                },
              ],
              value_type: 'string',
            },
            _typeCode: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Type code',
                },
                {
                  locale: 'de',
                  name: 'Typcode',
                },
              ],
              value_type: 'string',
            },
            validUntil: {
              mandatory: false,
              display: [
                {
                  locale: 'en',
                  name: 'Valid until',
                },
                {
                  locale: 'de',
                  name: 'Gültig bis',
                },
              ],
              value_type: 'string',
            },
          },
        },
      ])
    ).toEqual({
      'alpha-credential-1.0.0': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Profile Information', locale: 'en' },
            { name: 'Profilinformationen', locale: 'de' },
          ],
          claims: [
            {
              path: ['givenName'],
              mandatory: true,
              display: [
                { name: 'Given name', locale: 'en' },
                { name: 'Vorname', locale: 'de' },
              ],
            },
            {
              path: ['familyName'],
              mandatory: true,
              display: [
                { name: 'Family name', locale: 'en' },
                { name: 'Nachname', locale: 'de' },
              ],
            },
            {
              path: ['birthDate'],
              mandatory: true,
              display: [
                { name: 'Birth date', locale: 'en' },
                { name: 'Geburtsdatum', locale: 'de' },
              ],
            },
            {
              path: ['registrationId'],
              mandatory: true,
              display: [
                { name: 'Registration identifier', locale: 'en' },
                { name: 'Registrierungskennung', locale: 'de' },
              ],
            },
            {
              path: ['_fullRegistrationId'],
              mandatory: true,
              display: [
                { name: 'Complete registration identifier', locale: 'en' },
                { name: 'Vollständige Registrierungskennung', locale: 'de' },
              ],
            },
            {
              path: ['taxId'],
              mandatory: true,
              display: [
                { name: 'Tax identifier', locale: 'en' },
                { name: 'Steueridentifikator', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'ALPHA_TYPE',
      },
      'beta-entitlement-1.0.0': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Continental Access Pass', locale: 'en' },
            { name: 'Kontinentaler Zugangspass', locale: 'de' },
          ],
          claims: [
            {
              path: ['fullName'],
              mandatory: true,
              display: [
                { name: 'Full name', locale: 'en' },
                { name: 'Vollständiger Name', locale: 'de' },
              ],
            },
            {
              path: ['additionalNames'],
              mandatory: true,
              display: [
                { name: 'Additional names', locale: 'en' },
                { name: 'Zusätzliche Namen', locale: 'de' },
              ],
            },
            {
              path: ['birthDate'],
              mandatory: true,
              display: [
                { name: 'Birth date', locale: 'en' },
                { name: 'Geburtsdatum', locale: 'de' },
              ],
            },
            {
              path: ['subjectId'],
              mandatory: true,
              display: [
                { name: 'Subject identifier', locale: 'en' },
                { name: 'Subjektkennung', locale: 'de' },
              ],
            },
            {
              path: ['passId'],
              mandatory: true,
              display: [
                { name: 'Pass identifier', locale: 'en' },
                { name: 'Pass-Kennung', locale: 'de' },
              ],
            },
            {
              path: ['expirationDate'],
              mandatory: false,
              display: [
                { name: 'Expires on', locale: 'en' },
                { name: 'Gültig bis', locale: 'de' },
              ],
            },
            {
              path: ['orgId'],
              mandatory: true,
              display: [
                { name: 'Organization identifier', locale: 'en' },
                { name: 'Organisationskennung', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'BETA_TYPE',
      },
      'gamma-entitlement-1.1.0': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Premium Access', locale: 'en' },
            { name: 'Premium-Zugang', locale: 'de' },
          ],
          claims: [
            {
              path: ['givenName'],
              mandatory: true,
              display: [
                { name: 'Given name', locale: 'en' },
                { name: 'Vorname', locale: 'de' },
              ],
            },
            {
              path: ['familyName'],
              mandatory: true,
              display: [
                { name: 'Family name', locale: 'en' },
                { name: 'Nachname', locale: 'de' },
              ],
            },
            {
              path: ['birthDate'],
              mandatory: true,
              display: [
                { name: 'Birth date', locale: 'en' },
                { name: 'Geburtsdatum', locale: 'de' },
              ],
            },
            {
              path: ['category'],
              mandatory: true,
              display: [
                { name: 'Category', locale: 'en' },
                { name: 'Kategorie', locale: 'de' },
              ],
            },
            {
              path: ['providerName'],
              mandatory: true,
              display: [
                { name: 'Provider name', locale: 'en' },
                { name: 'Anbietername', locale: 'de' },
              ],
            },
            {
              path: ['visibleAccessId'],
              mandatory: true,
              display: [
                { name: 'Access identifier', locale: 'en' },
                { name: 'Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_internalAccessId'],
              mandatory: true,
              display: [
                { name: 'Internal access identifier', locale: 'en' },
                { name: 'Interne Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_typeCode'],
              mandatory: false,
              display: [
                { name: 'Type code', locale: 'en' },
                { name: 'Typcode', locale: 'de' },
              ],
            },
            {
              path: ['validUntil'],
              mandatory: false,
              display: [
                { name: 'Valid until', locale: 'en' },
                { name: 'Gültig bis', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'GAMMA_TYPE',
      },
      'delta-entitlement-1.1.0': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Service Access', locale: 'en' },
            { name: 'Dienstzugang', locale: 'de' },
          ],
          claims: [
            {
              path: ['givenName'],
              mandatory: true,
              display: [
                { name: 'Given name', locale: 'en' },
                { name: 'Vorname', locale: 'de' },
              ],
            },
            {
              path: ['familyName'],
              mandatory: true,
              display: [
                { name: 'Family name', locale: 'en' },
                { name: 'Nachname', locale: 'de' },
              ],
            },
            {
              path: ['birthDate'],
              mandatory: true,
              display: [
                { name: 'Birth date', locale: 'en' },
                { name: 'Geburtsdatum', locale: 'de' },
              ],
            },
            {
              path: ['category'],
              mandatory: true,
              display: [
                { name: 'Category', locale: 'en' },
                { name: 'Kategorie', locale: 'de' },
              ],
            },
            {
              path: ['providerName'],
              mandatory: true,
              display: [
                { name: 'Provider name', locale: 'en' },
                { name: 'Anbietername', locale: 'de' },
              ],
            },
            {
              path: ['visibleAccessId'],
              mandatory: true,
              display: [
                { name: 'Access identifier', locale: 'en' },
                { name: 'Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_internalAccessId'],
              mandatory: true,
              display: [
                { name: 'Internal access identifier', locale: 'en' },
                { name: 'Interne Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_typeCode'],
              mandatory: false,
              display: [
                { name: 'Type code', locale: 'en' },
                { name: 'Typcode', locale: 'de' },
              ],
            },
            {
              path: ['validUntil'],
              mandatory: false,
              display: [
                { name: 'Valid until', locale: 'en' },
                { name: 'Gültig bis', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'DELTA_TYPE',
      },
      'epsilon-entitlement-1.0.1': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Extended Coverage Program', locale: 'en' },
            { name: 'Erweitertes Versorgungsprogramm', locale: 'de' },
          ],
          claims: [
            {
              path: ['givenName'],
              mandatory: true,
              display: [
                { name: 'Given name', locale: 'en' },
                { name: 'Vorname', locale: 'de' },
              ],
            },
            {
              path: ['familyName'],
              mandatory: true,
              display: [
                { name: 'Family name', locale: 'en' },
                { name: 'Nachname', locale: 'de' },
              ],
            },
            {
              path: ['birthDate'],
              mandatory: true,
              display: [
                { name: 'Birth date', locale: 'en' },
                { name: 'Geburtsdatum', locale: 'de' },
              ],
            },
            {
              path: ['category'],
              mandatory: true,
              display: [
                { name: 'Category', locale: 'en' },
                { name: 'Kategorie', locale: 'de' },
              ],
            },
            {
              path: ['providerName'],
              mandatory: true,
              display: [
                { name: 'Provider name', locale: 'en' },
                { name: 'Anbietername', locale: 'de' },
              ],
            },
            {
              path: ['visibleAccessId'],
              mandatory: true,
              display: [
                { name: 'Access identifier', locale: 'en' },
                { name: 'Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_internalAccessId'],
              mandatory: true,
              display: [
                { name: 'Internal access identifier', locale: 'en' },
                { name: 'Interne Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_typeCode'],
              mandatory: false,
              display: [
                { name: 'Type code', locale: 'en' },
                { name: 'Typcode', locale: 'de' },
              ],
            },
            {
              path: ['validUntil'],
              mandatory: false,
              display: [
                { name: 'Valid until', locale: 'en' },
                { name: 'Gültig bis', locale: 'de' },
              ],
            },
            {
              path: ['programCode'],
              mandatory: true,
              display: [
                { name: 'Program code', locale: 'en' },
                { name: 'Programmcode', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'EPSILON_TYPE',
      },
      'zeta-entitlement-1.1.0': {
        format: 'dc+sd-jwt',
        credential_metadata: {
          display: [
            { name: 'Cost Reduction Scheme', locale: 'en' },
            { name: 'Kostensenkungsprogramm', locale: 'de' },
          ],
          claims: [
            {
              path: ['givenName'],
              mandatory: true,
              display: [
                { name: 'Given name', locale: 'en' },
                { name: 'Vorname', locale: 'de' },
              ],
            },
            {
              path: ['familyName'],
              mandatory: true,
              display: [
                { name: 'Family name', locale: 'en' },
                { name: 'Nachname', locale: 'de' },
              ],
            },
            {
              path: ['category'],
              mandatory: true,
              display: [
                { name: 'Category', locale: 'en' },
                { name: 'Kategorie', locale: 'de' },
              ],
            },
            {
              path: ['visibleAccessId'],
              mandatory: true,
              display: [
                { name: 'Access identifier', locale: 'en' },
                { name: 'Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_internalAccessId'],
              mandatory: true,
              display: [
                { name: 'Internal access identifier', locale: 'en' },
                { name: 'Interne Zugangskennung', locale: 'de' },
              ],
            },
            {
              path: ['_typeCode'],
              mandatory: false,
              display: [
                { name: 'Type code', locale: 'en' },
                { name: 'Typcode', locale: 'de' },
              ],
            },
            {
              path: ['validUntil'],
              mandatory: false,
              display: [
                { name: 'Valid until', locale: 'en' },
                { name: 'Gültig bis', locale: 'de' },
              ],
            },
          ],
        },
        vct: 'ZETA_TYPE',
      },
    })
  })

  test('claimsObjectToClaimsArray transforms draft 14 claims to array syntax', () => {
    const claimsDraft14 = {
      firstName: {
        mandatory: true,
        display: [
          {
            locale: 'en',
            name: 'First name',
          },
          {
            locale: 'ga',
            name: 'Céadainm',
          },
        ],
        value_type: 'string',
      },
      lastName: {
        mandatory: true,
        display: [
          {
            locale: 'en',
            name: 'Last name',
          },
        ],
        value_type: 'string',
      },
      address: {
        street: {
          mandatory: false,
          value_type: 'string',
        },
        city: {
          mandatory: true,
          value_type: 'string',
        },
      },
    }

    const result = claimsObjectToClaimsArray(claimsDraft14)

    expect(result).toEqual([
      {
        path: ['firstName'],
        mandatory: true,
        display: [
          {
            locale: 'en',
            name: 'First name',
          },
          {
            locale: 'ga',
            name: 'Céadainm',
          },
        ],
      },
      {
        path: ['lastName'],
        mandatory: true,
        display: [
          {
            locale: 'en',
            name: 'Last name',
          },
        ],
      },
      {
        path: ['address', 'street'],
        mandatory: false,
      },
      {
        path: ['address', 'city'],
        mandatory: true,
      },
    ])
  })

  test('claimsObjectToClaimsArray returns undefined for invalid input', () => {
    expect(claimsObjectToClaimsArray('invalid')).toBeUndefined()
    expect(claimsObjectToClaimsArray(null)).toBeUndefined()
    expect(claimsObjectToClaimsArray(123)).toBeUndefined()
  })

  test('claimsObjectToClaimsArray handles empty object', () => {
    const result = claimsObjectToClaimsArray({})
    expect(result).toEqual([])
  })

  test('claimsObjectToClaimsArray handles deeply nested claims', () => {
    const claimsDraft14 = {
      credential: {
        subject: {
          name: {
            mandatory: true,
            value_type: 'string',
          },
        },
      },
    }

    const result = claimsObjectToClaimsArray(claimsDraft14)

    expect(result).toEqual([
      {
        path: ['credential', 'subject', 'name'],
        mandatory: true,
      },
    ])
  })
})
