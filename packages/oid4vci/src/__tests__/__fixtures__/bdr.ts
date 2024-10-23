export const bdrDraft13 = {
  credentialOffer:
    'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fdemo.pid-issuer.bundesdruckerei.de%2Fc%22%2C%22credential_configuration_ids%22%3A%5B%22pid-sd-jwt%22%2C%20%22pid-mso-mdoc%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%7D%7D%7D',
  credentialOfferObject: {
    credential_issuer: 'https://demo.pid-issuer.bundesdruckerei.de/c',
    credential_configuration_ids: ['pid-sd-jwt', 'pid-mso-mdoc'],
    grants: { authorization_code: {} },
  },
  authorizationServerMetadata: {
    issuer: 'https://demo.pid-issuer.bundesdruckerei.de/c',
    authorization_endpoint: 'https://demo.pid-issuer.bundesdruckerei.de/c/authorize',
    token_endpoint: 'https://demo.pid-issuer.bundesdruckerei.de/c/token',
    pushed_authorization_request_endpoint: 'https://demo.pid-issuer.bundesdruckerei.de/c/par',
    require_pushed_authorization_requests: true,
    token_endpoint_auth_methods_supported: ['none'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    dpop_signing_alg_values_supported: [
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES256K',
      'ES384',
      'ES512',
      'EdDSA',
      'Ed25519',
      'Ed448',
    ],
  },
  credentialIssuerMetadata: {
    credential_issuer: 'https://demo.pid-issuer.bundesdruckerei.de/c',
    credential_endpoint: 'https://demo.pid-issuer.bundesdruckerei.de/c/credential',
    display: [
      {
        name: 'Bundesdruckerei GmbH',
        locale: 'de-DE',
      },
      {
        name: 'Bundesdruckerei GmbH',
        locale: 'en-US',
      },
    ],
    credential_configurations_supported: {
      'pid-sd-jwt': {
        scope: 'pid',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        vct: 'https://example.bmi.bund.de/credential/pid/1.0',
        format: 'vc+sd-jwt',
      },
      'pid-mso-mdoc': {
        scope: 'pid',
        cryptographic_binding_methods_supported: ['cose_key'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        doctype: 'eu.europa.ec.eudi.pid.1',
        format: 'mso_mdoc',
      },
    },
  },
  pushedAuthorizationResponse: {
    request_uri: 'urn:ietf:params:oauth:request_uri:hvbhS1BHhHZzZbwEbBwK2Y',
    expires_in: 60,
  },
  authorizationRequestUrl:
    'https://demo.pid-issuer.bundesdruckerei.de/c/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3AhvbhS1BHhHZzZbwEbBwK2Y&client_id=76c7c89b-8799-4bd1-a693-d49948a91b00',
  accessTokenResponse: {
    access_token: 'yvFUHf7pZBfgHd6pkI1ktc',
    token_type: 'DPoP',
    expires_in: 3600,
    c_nonce: 'sjNMiqyfmBeD1qioCVyqvS',
    c_nonce_expires_in: 3600,
  },
  credentialResponse: {
    credential:
      'eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpRd05UTXhNRGd4TXpFM1doY05NalV3TnpBMU1EZ3hNekUzV2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU9GQnE0WU1LZzR3NWZUaWZzeXR3QnVKZi83RTdWaFJQWGlObTUyUzNxMUVUSWdCZFh5REsza1Z4R3hnZUhQaXZMUDN1dU12UzZpREVjN3FNeG12ZHVLT0JrRENCalRBZEJnTlZIUTRFRmdRVWlQaENrTEVyRFhQTFcyL0owV1ZlZ2h5dyttSXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUFiZjVUemtjUXpoZldvSW95aTFWTjdkOEk5QnNGS20xTVdsdVJwaDJieUdRSWdLWWtkck5mMnhYUGpWU2JqVy9VLzVTNXZBRUM1WHhjT2FudXNPQnJvQmJVPSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkFnPT0iLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJwbGFjZV9vZl9iaXJ0aCI6eyJfc2QiOlsiOGFRMFpkRHRpVWd5N3FhY1dpcmZWci1sN3NLUXQzckFNNmIwSnFHSjJIUSJdfSwiX3NkIjpbIjVEZFN6SXRLUmhrMmJEUm5yREhGTjE4MmFDeVFkem9YU2xVTXlYelk0M28iLCI2ajdZMmFSYWcwRjZLQzVVNnh6RUp3QklQZTFUOE0tSGVhclJlOFBqSkFjIiwiRlVaSUNaWm9uLThvMGZqVk5QMS1IcmZ2dWhfcjgyQlJ4eVZIZTBoS1BIbyIsIk1KNGZwT1FuLXJ4S242bzBHTi12YUh5VmZIQWhaNTF6WklaZXkybWhVWU0iLCJmMFNJWDJicXZUS3JxMk1rdjJUSE9ReVVQSnhUdkNmNkRESEZ1b1lMTXMwIiwicWU0UlVNUjJfVEtZM0UxUm94TjY2RlhRR1FNTlpKV2tRRnJMOHBJNWJhVSIsInZqSFZ4ellINDBsNjY2SnlEcF80Tkt5NnJIWkVya0wwVEJEbEswVWxQYlkiXSwiYWRkcmVzcyI6eyJfc2QiOlsiMTJpSW1FZDQ3YVdocnVMZ05QZ3QtNnBVTF9sNHFTSmlCTUFfdUl3UWk3NCIsIjFic04zS0dFM2hrOVpVdUpxXzN5cTRIdUhxRi1LcWIyTjllaWR3dFR5d1UiLCJRVEV1cTdfZEdsWDBzNUE0bjRLWVNBUEFQaW5kWTZYZGwxdjJUR3cyUXFVIiwiakNNeThTVWtpTmNqcGZsTGpvRTUzM2VHX3R1NnQ2aUEweGo1RTdPRzNNcyJdfSwiaXNzdWluZ19jb3VudHJ5IjoiREUiLCJ2Y3QiOiJodHRwczovL2V4YW1wbGUuYm1pLmJ1bmQuZGUvY3JlZGVudGlhbC9waWQvMS4wIiwiaXNzdWluZ19hdXRob3JpdHkiOiJERSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9kZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlL2MiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQUVYcEh5MTBHaHRXaGxWUE5tckZzYnl0X3dEc1FfN3EzZGpObnJoempfNCIsInkiOiJER1RBQ09BQW5RVGVwYUQ0MGd5RzlabC1vRGhPbHYzVUJsVHR4SWVyNWVvIn19LCJleHAiOjE3MzA5MDc5MjIsImlhdCI6MTcyOTY5ODMyMiwiYWdlX2VxdWFsX29yX292ZXIiOnsiX3NkIjpbIjlDMmk2MVp3bDhWdmE0a09PX3U5UnZ1c0RhYjZXVGlCeUlteEtmd3VROUUiLCJlV1NxQXY5RHY5VzdzNzZwZVFRWWtjV1N1Wlc2M0ZnaDNmZUY2S19oLVE0IiwiZ1lXWmRETlFhTHRrWXlrUDBvclB5SUtIVEl3Z3RYb2dmdWxCY2o4MVFKMCIsInBFQ2dMLTN6QmVHQzZhT20zcXY4ZkZ2R1pZRmZGRERacktRQThicl9fdWsiLCJzSWRxRy14aE96bmRkdW9HVjVRVnhBYU9MT1UxZV8zMjhaV3hoeUdBcUpRIiwieFdkQVRkclZ2R2t1ZE94aWpFby1zT3NlY2JhemUtSHJickZDQk9GNlUtOCJdfX0.PA0jtVtgKqPFr1IDVAxXKL5YSUWqLLoFsJz9cJ9rhr24g44Tu-7ZIAU9Ic9KgUGCHak5RkbL8Y87PeflVQkC1Q~WyJhNFZyamZSVWtKcGE1eThjcVVncTRnIiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0~WyJ2WEhHdUt1VGZXeW9zMEthRzFwQndnIiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0~WyIwQXd3d0hGT290TVFIQkJHendycUZnIiwiYmlydGhkYXRlIiwiMTk2NC0wOC0xMiJd~WyJoR1NkcGNBcjI4cnYybDFzSUZKTGhBIiwiYWdlX2JpcnRoX3llYXIiLDE5NjRd~WyI4aEV2Y3lDejkzdDdUcmpLb29Wd2lBIiwiYWdlX2luX3llYXJzIiw2MF0~WyJqMk9XdGNod2hGaW5CMVJleHJNeGlRIiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ~WyJXZ0ZRS2xpdEszSlNIcWZqdFh3R1RnIiwibmF0aW9uYWxpdGllcyIsWyJERSJdXQ~WyJBYl9ZcVlyVUJ2U1I4M1FXT240SVlBIiwiMTIiLHRydWVd~WyJrQkhXbXJEZFpReEtUcDFMSjRmcGd3IiwiMTQiLHRydWVd~WyJqcVlhd3JTd3BiZEJaTDdzLTNjbXpRIiwiMTYiLHRydWVd~WyJ2ZXZkMUhrRHhmblFURVoxeWJOalN3IiwiMTgiLHRydWVd~WyJ6OHBjU004NnRwWGRZUjFTTGk1TW1nIiwiMjEiLHRydWVd~WyJBTGVzdkNfUXdPazdrRHVfajB0X25RIiwiNjUiLGZhbHNlXQ~WyJkUU9GQ1dmQWdXZUc2dkpyd0ptekt3IiwibG9jYWxpdHkiLCJCRVJMSU4iXQ~WyJSQ05jdlZXUDRGWHIyaktOWWhYV0ZRIiwibG9jYWxpdHkiLCJLw5ZMTiJd~WyIwMEJITldDRG5KZGFUYWFhdjFJNHlRIiwiY291bnRyeSIsIkRFIl0~WyJ5SkhwdktYOU1iNFlmdXBBNHRNN1l3IiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd~WyJXZlAyYndtQTh1VXZCRG4zQTRVcFpRIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkHhup5FIDE3Il0~',
    c_nonce: 'K7fOJwQEUYYg3e4f0jbmCg',
    c_nonce_expires_in: 3600,
  },
  holderPrivateKeyJwk: {
    kty: 'EC',
    x: 'AEXpHy10GhtWhlVPNmrFsbyt_wDsQ_7q3djNnrhzj_4',
    y: 'DGTACOAAnQTepaD40gyG9Zl-oDhOlv3UBlTtxIer5eo',
    crv: 'P-256',
    d: 'C75pQj72AAl6SCsBW8AKTKxqLGk2Fw7NutIpWZ-xjvE',
  },
  dpopPrivateKeyJwk: {
    kty: 'EC',
    x: 'TSSFq4BS2ylSHJ9Ghh86NbBj0EbqZLD09seVVUETwuw',
    y: 'e758NDPPZf9s6siLNk4h6bQC03eVHP1qTit37OOCIg4',
    crv: 'P-256',
    d: 'PBsZ0X1NnZrXqr1X77TtVQM2BVM2yxjq-FolyGd4EYM',
  },
}
