import { ValidationError } from '@openid4vc/utils'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { Oauth2Error } from '../error/Oauth2Error'
import { fetchAuthorizationServerMetadata } from '../metadata/authorization-server/authorization-server-metadata'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

const server = setupServer()

const issuer = 'https://authorization-server.com'
const authorizationServerMetadata = {
  issuer,
  token_endpoint: 'https://authorization-server.com/token',
  jwks_uri: 'https://authorization-server.com/jwks.json',
} satisfies AuthorizationServerMetadata

describe('fetchAuthorizationServerMetadata', () => {
  beforeAll(() => server.listen())
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  test('uses metadata from the getAuthorizationServerMetadata callback without performing a request', async () => {
    let wellKnownRequestCount = 0
    server.resetHandlers(
      http.get('https://authorization-server.com/.well-known/*', () => {
        wellKnownRequestCount++
        return HttpResponse.json(authorizationServerMetadata)
      })
    )

    const requestedIssuers: string[] = []
    const metadata = await fetchAuthorizationServerMetadata(issuer, {
      fetch,
      getAuthorizationServerMetadata: (requestedIssuer) => {
        requestedIssuers.push(requestedIssuer)
        return authorizationServerMetadata
      },
    })

    expect(metadata).toEqual(authorizationServerMetadata)
    expect(requestedIssuers).toEqual([issuer])
    expect(wellKnownRequestCount).toEqual(0)
  })

  test('returns null without performing a request if the callback returns null', async () => {
    let wellKnownRequestCount = 0
    server.resetHandlers(
      http.get('https://authorization-server.com/.well-known/*', () => {
        wellKnownRequestCount++
        return HttpResponse.json(authorizationServerMetadata)
      })
    )

    const metadata = await fetchAuthorizationServerMetadata(issuer, {
      fetch,
      getAuthorizationServerMetadata: () => null,
    })

    expect(metadata).toBeNull()
    expect(wellKnownRequestCount).toEqual(0)
  })

  test('falls back to fetching if the callback returns undefined', async () => {
    let wellKnownRequestCount = 0
    server.resetHandlers(
      http.get('https://authorization-server.com/.well-known/oauth-authorization-server', () => {
        wellKnownRequestCount++
        return HttpResponse.json(authorizationServerMetadata)
      })
    )

    const metadata = await fetchAuthorizationServerMetadata(issuer, {
      fetch,
      getAuthorizationServerMetadata: () => undefined,
    })

    expect(metadata).toEqual(authorizationServerMetadata)
    expect(wellKnownRequestCount).toEqual(1)
  })

  test('throws if the callback returns metadata that does not pass validation', async () => {
    await expect(
      fetchAuthorizationServerMetadata(issuer, {
        fetch,
        // Missing the required `token_endpoint`
        getAuthorizationServerMetadata: () => ({ issuer }) as AuthorizationServerMetadata,
      })
    ).rejects.toThrow(ValidationError)
  })

  test('throws if the callback returns metadata for a different issuer', async () => {
    await expect(
      fetchAuthorizationServerMetadata(issuer, {
        fetch,
        getAuthorizationServerMetadata: () => ({
          ...authorizationServerMetadata,
          issuer: 'https://another-authorization-server.com',
        }),
      })
    ).rejects.toThrow(Oauth2Error)
  })
})
