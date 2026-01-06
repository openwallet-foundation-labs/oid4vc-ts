// https://procivis.sandbox.findy.fi/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/df0fc41b-f631-4f3c-b4ba-6b9e13c75e54
export const findyProvicisCredentialIssuerMetadataJson = {
  credential_issuer: 'https://procivis.sandbox.findy.fi/ssi/openid4vci/final-1.0/df0fc41b-f631-4f3c-b4ba-6b9e13c75e54',
  credential_endpoint:
    'https://procivis.sandbox.findy.fi/ssi/openid4vci/final-1.0/df0fc41b-f631-4f3c-b4ba-6b9e13c75e54/credential',
  nonce_endpoint: 'https://procivis.sandbox.findy.fi/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce',
  notification_endpoint:
    'https://procivis.sandbox.findy.fi/ssi/openid4vci/final-1.0/df0fc41b-f631-4f3c-b4ba-6b9e13c75e54/notification',
  credential_configurations_supported: {
    'https://alennusperuste.todiste.fi/credentials/v1/PensionCredential': {
      format: 'dc+sd-jwt',
      vct: 'https://alennusperuste.todiste.fi/credentials/v1/PensionCredential',
      credential_metadata: {
        display: [
          {
            name: 'Eläkeläistodiste',
            locale: 'en',
            logo: {
              uri: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADYAAAA2CAYAAACMRWrdAAAAAXNSR0IArs4c6QAABTBJREFUaEPdWjFoFUEQnfukMIUJWigoX4uACv7CIikMaKEgWmqjZaqUsdHSRsvYaKmNpTamFAQtFGORFBZfUCGFBAJaRGKKWIS/8ub/S/Z2Z3dnL5cYXAiBu/uz82Z3Zt7MbmGMMfQfjmLXgG0sk1nvEuFv83f/vzsOTRINjRId7FBxeLJR8zYLbL1LZuUFmZ+viDaWsxUtjlwjOnKV+D8A72A0AsysPCfz/am8KjWVK47domLsDtFwu5aEHQEzq/NkPs/UWh2ttgzwzP3sFawHbHONTPd2f8vtxRgaZXAAqR35wNa71Fu4QbS5pp2jse9yVi8LGPtS9zYrWpx+QMVIp6K0+d0l8/WeB6Q4dpOK4761ewvXfdAHO9Q688B73vtyr+/DeD/xMrk11cBsUJi1NTFHhHBtj1/zJClbjN3tBwJn9F4f9Y1weJKK8TnvOQxmvj/pP1eAUwFzQTGwKz98a2N7rn/2nx9oy9Ht17z/7dAIK+4Os/SQzNLs9uMEuDQw+NTHy95EIrDGvMkXhNVytzmSurS67CpR5rG5Rr13E36gGG5T68LiLsIQRIe2+clp9nd3RIGZT1NiSI9ZatfQBoDx6ozPeZQsCIyT76IQtSAosgV2DdjGMvXej8vi4W/n31TeBYGxkADfKwLLHwMFDmnLQwrIpUtSFC3nLDqPKglcBCZFQVvpUPgWgSH4fJoSjZRroBgwGMn2exEYR0GpzBhorgaG7QNZEZaSAy6pl7VqPrBAeLdXQ0zOwnKZ7gyXManB/iHkLi+XLV4n+H5o2L7vAatk+IAELbDe21MqTqndAaEoXTE60tBw289jqeWGEN7Lijop6hOWNtoo67EPwfBlEKmuGBIyrJwYWtahBgaS3HmcmpZUwFC/wdds5hHLXZXllniioFYsZVSibOcxcfhPDG47dGfiXw2iYxXY0ixbJTqEZBj6XqXI0Ci1Li4kyxCeI8I+XMNnA9P6QzlRNDICFGorRUTMAnb+jbMVE+EUwtFBKs49S+2aynteOZQcFpNhOajRtKAgURkDmDtWfEwDLFA0qpAiUQNcDhhHsCYg7T0wFfr4R5rcWA+YMoI1gEEUgYojxj7YXbytiJbayvOoTlrWsb+AKcL9Pwem4J+tS9+c4GG110IWx4/q9NWZDK9+IPrTDx7FiWkVLXP10LAPMKMqpdIweyXr2FIIIRoNVqEM0pJfG1wKWJlnPXYfjTpIqFixjJEi1dx4PTmtl5hgH8iNbDC3SxUrDbJZh4bb5VAqBa0qGzs+sIifZQNThGbomhWQYu5i7Si/gg71EpEflOXFFk9UAsvdjiH2YbcZ5GZOIJ/lOruG/nBCzaRpIbl2ASy33wI9vKYUcCNFtlyhNchHTJ1HW6LDDVP7dGPwOVg9nw9rRqzB6fy+Cd912xXhFrfga1lOriwKeStmdpZdvii18OK9+5+vCOG/HNo2GX+fAcxtdqY2RCVJoxWA9p1zyyB5jMRnzQNirG3iQDHp2CemcJbs8qwsUoEngUGZkj3Umjxl/sH7OrLdfr09lQoYl+QBvqfUu/HPYqDYb9VXjvYRuBSoPGD4eq/vd7jrnHHfQ79i1iToOCX7j01vPvQzkYCVjaBawFhnXAhDEo+cfjSFjUsRlDYZF8fqAxtozYeE6B7XuO2WAr6Ti2I7BlYqx/eqyit9KY1j73EEhGZqzdZBKboxYFu6IsAA5OrH7YuYMSAICCNn+ZYP81ClD6Vs1zwwaUbcNhW2atO3SvMTdMo8+/D93qzYPwD+F2vKeb95roK9AAAAAElFTkSuQmCC',
              alt_text: 'Eläkeläistodiste logo',
            },
            background_color: '#0a00be',
            procivis_design: { primary_attribute: 'Pension/typeName', secondary_attribute: 'Person/family_name' },
          },
        ],
        claims: [
          { path: ['Pension', 'endDate'], display: [{ name: 'endDate', locale: 'en' }], mandatory: false },
          { path: ['Pension', 'startDate'], display: [{ name: 'startDate', locale: 'en' }], mandatory: true },
          { path: ['Pension', 'provisional'], display: [{ name: 'provisional', locale: 'en' }], mandatory: false },
          { path: ['Pension', 'typeCode'], display: [{ name: 'typeCode', locale: 'en' }], mandatory: true },
          { path: ['Pension', 'typeName'], display: [{ name: 'typeName', locale: 'en' }], mandatory: true },
          {
            path: ['Person', 'personal_administrative_number'],
            display: [{ name: 'personal_administrative_number', locale: 'en' }],
            mandatory: true,
          },
          { path: ['Person', 'birth_date'], display: [{ name: 'birth_date', locale: 'en' }], mandatory: false },
          { path: ['Person', 'family_name'], display: [{ name: 'family_name', locale: 'en' }], mandatory: false },
          { path: ['Person', 'given_name'], display: [{ name: 'given_name', locale: 'en' }], mandatory: false },
        ],
      },
      scope: 'https://alennusperuste.todiste.fi/credentials/v1/PensionCredential',
      cryptographic_binding_methods_supported: ['jwk', 'did:key', 'did:web', 'did:jwk', 'did:ion', 'did:tdw'],
      credential_signing_alg_values_supported: ['ES256', 'EdDSA', 'CRYDI3'],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ['CRYDI3', 'DILITHIUM', 'ES256', 'BBS_PLUS', 'EdDSA', 'EDDSA'],
          key_attestations_required: null,
        },
      },
    },
  },
  display: [{ name: 'kela.pensiondemo.findy.fi', locale: 'en' }],
}
