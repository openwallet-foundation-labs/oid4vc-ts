import { ContentType } from '@openid4vc/utils'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { callbacks } from '../../../tests/util.mjs'
import type { SignJwtCallback } from '../../callbacks'
import { Oauth2ClientErrorResponseError } from '../../error/Oauth2ClientErrorResponseError'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import {
  type RetrieveClientCredentialsAccessTokenOptions,
  retrieveClientCredentialsAccessToken,
} from '../retrieve-access-token'
import type { AccessTokenResponse } from '../z-access-token'

const server = setupServer()

const mockAuthorizationServerMetadata: AuthorizationServerMetadata = {
  issuer: 'https://auth.example.com',
  token_endpoint: 'https://auth.example.com/token',
  authorization_endpoint: 'https://auth.example.com/authorize',
}

// Mock signJwt callback that's not actually used in client credentials flow
const mockSignJwt: SignJwtCallback = async () => {
  throw new Error('signJwt should not be called in client credentials flow')
}

describe('retrieveClientCredentialsAccessToken', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  test('should successfully retrieve access token with client credentials', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read write',
    }

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).toContain('scope=read+write')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      scope: 'read write',
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should work without scope parameter', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    }

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).not.toContain('scope=')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should include resource in the request when provided', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    }

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).toContain('resource=https%3A%2F%2Fapi.example.com')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      resource: 'https://api.example.com',
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should handle token error response', async () => {
    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, () => {
        return HttpResponse.json(
          {
            error: 'invalid_client',
            error_description: 'Client authentication failed',
          },
          {
            status: 400,
            headers: { 'Content-Type': ContentType.Json },
          }
        )
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    await expect(retrieveClientCredentialsAccessToken(options)).rejects.toThrow(Oauth2ClientErrorResponseError)
  })

  test('should handle invalid response', async () => {
    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, () => {
        return new HttpResponse('Internal Server Error', {
          status: 500,
          headers: { 'Content-Type': 'text/plain' },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    await expect(retrieveClientCredentialsAccessToken(options)).rejects.toThrow()
  })

  test('should include additional request payload', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    }

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).toContain('custom_param=custom_value')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      additionalRequestPayload: {
        custom_param: 'custom_value',
      },
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should include both scope and resource', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read write',
    }

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).toContain('scope=read+write')
        expect(body).toContain('resource=https%3A%2F%2Fapi.example.com')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      scope: 'read write',
      resource: 'https://api.example.com',
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should use client_secret_post authentication when provided', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    }

    const clientId = 'test_client_id'
    const clientSecret = 'test_client_secret'

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        expect(body).toContain(`client_id=${clientId}`)
        expect(body).toContain(`client_secret=${clientSecret}`)

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
        clientAuthentication: async ({ body }) => {
          body.client_id = clientId
          body.client_secret = clientSecret
        },
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })

  test('should use client_secret_basic authentication when provided', async () => {
    const mockResponse: AccessTokenResponse = {
      access_token: 'test_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    }

    const clientId = 'test_client_id'
    const clientSecret = 'test_client_secret'

    server.resetHandlers(
      http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        expect(authHeader).toBeDefined()
        expect(authHeader).toContain('Basic ')

        // Decode and verify the Basic auth credentials
        const encodedCredentials = authHeader?.split(' ')[1]
        const decodedCredentials = atob(encodedCredentials || '')
        expect(decodedCredentials).toBe(`${clientId}:${clientSecret}`)

        const body = await request.text()
        expect(body).toContain('grant_type=client_credentials')
        // Should NOT contain client_id/client_secret in body for basic auth
        expect(body).not.toContain('client_id=')
        expect(body).not.toContain('client_secret=')

        return HttpResponse.json(mockResponse, {
          headers: { 'Content-Type': ContentType.Json },
        })
      })
    )

    const options: RetrieveClientCredentialsAccessTokenOptions = {
      authorizationServerMetadata: mockAuthorizationServerMetadata,
      callbacks: {
        ...callbacks,
        signJwt: mockSignJwt,
        fetch,
        clientAuthentication: async ({ headers }) => {
          const credentials = btoa(`${clientId}:${clientSecret}`)
          headers.set('Authorization', `Basic ${credentials}`)
        },
      },
    }

    const result = await retrieveClientCredentialsAccessToken(options)

    expect(result.accessTokenResponse).toEqual(mockResponse)
  })
})
