import { ContentType } from '@openid4vc/utils'
import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../tests/util'
import { Oauth2ResourceServer } from '../Oauth2ResourceServer'
import { createAccessTokenJwt } from '../access-token/create-access-token'
import type { Jwk, JwkSet } from '../common/jwk/z-jwk'
import { createDpopJwt } from '../dpop/dpop'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

const server = setupServer()

const dpopSignerJwk = {
  kty: 'EC',
  d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
  crv: 'P-256',
  x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
  y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
} satisfies Jwk
const { d: _, ...dpopSignerJwkPublic } = dpopSignerJwk

const accessTokenSignerJwk = {
  kid: 'access-token-key',
  kty: 'EC',
  d: 'V_ksBfnmJBl9vU-GLs3LiNxgA3PV8he5u7NOYqcDWfo',
  crv: 'P-256',
  x: 'rQbiDHRutR4YcJaWRV54Dx-sx81VlK7xuohm4-RXRT0',
  y: 'YM4MRy90G9PW59wKcawyrHDCPp7QsE6l5QT-H2Koz_M',
} satisfies Jwk

const { d: __, ...accessTokenSignerJwkPublic } = accessTokenSignerJwk

const authorizationServerMetadata = {
  issuer: 'https://authorization-server.com',
  token_endpoint: 'https://authorization-server.com/token',
  jwks_uri: 'https://authorization-server.com/jwks.json',
} satisfies AuthorizationServerMetadata

describe('Oauth2ResourceServer', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('verifies resource request', async () => {
    server.resetHandlers(
      http.get(authorizationServerMetadata.jwks_uri, () =>
        HttpResponse.json({ keys: [accessTokenSignerJwkPublic] } satisfies JwkSet, {
          headers: { 'Content-Type': ContentType.JwkSet },
        })
      )
    )

    const resourceServer = new Oauth2ResourceServer({
      callbacks: {
        ...callbacks,
        fetch,
      },
    })

    const { jwt } = await createAccessTokenJwt({
      audience: 'https://resource-server.com',
      authorizationServer: authorizationServerMetadata.issuer,
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk, accessTokenSignerJwk]),
      },
      expiresInSeconds: 300,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: accessTokenSignerJwkPublic,
      },
      subject: 'pre-auth-code',
      dpopJwk: dpopSignerJwkPublic,
      now: new Date('2024-10-01'),
      scope: 'PidSdJwt PidMdoc',
    })

    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk, accessTokenSignerJwk]),
      },
      request: {
        method: 'POST',
        url: 'https://resource-server.com/endpoint',
      },
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerJwkPublic,
      },
      accessToken: jwt,
    })

    const { dpopJwk, tokenPayload } = await resourceServer.verifyResourceRequest({
      authorizationServers: [authorizationServerMetadata],
      request: {
        method: 'POST',
        url: 'https://resource-server.com/endpoint',
        headers: new Headers({
          Authorization: `DPoP ${jwt}`,
          DPoP: dpopJwt,
        }),
      },
      now: new Date('2024-10-01'),
      resourceServer: 'https://resource-server.com',
    })

    expect(dpopJwk).toEqual(dpopSignerJwkPublic)
    expect(tokenPayload).toEqual({
      aud: 'https://resource-server.com',
      cnf: {
        jkt: '-ROyTPYQqpxRbFqDVzNZrt_U0-zeAz0Wxmpv4TxlgLM',
      },
      exp: 1727741100,
      iat: 1727740800,
      iss: 'https://authorization-server.com',
      jti: expect.any(String),
      scope: 'PidSdJwt PidMdoc',
      sub: 'pre-auth-code',
    })
  })
})
