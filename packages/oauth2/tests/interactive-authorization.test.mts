import * as jose from 'jose'
import { describe, expect, test } from 'vitest'
import {
  type AuthorizationServerMetadata,
  type InteractiveAuthorizationFollowUpRequest,
  type InteractiveAuthorizationRequest,
  type Jwk,
  Oauth2AuthorizationServer,
  Oauth2Client,
  Oauth2ErrorCodes,
  Oauth2ServerErrorResponseError,
} from '../src/index.js'
import { callbacks, getSignJwtCallback } from './util.mjs'

async function generateJwkKeyPair(): Promise<{ publicKey: Jwk; privateKey: Jwk }> {
  const keyPair = await jose.generateKeyPair('ES256', { extractable: true })
  const publicKey = await jose.exportJWK(keyPair.publicKey)
  const privateKey = await jose.exportJWK(keyPair.privateKey)
  return {
    publicKey: publicKey as Jwk,
    privateKey: privateKey as Jwk,
  }
}

function createJwtSigner(options: { method: 'jwk'; alg: string; publicJwk: Jwk }) {
  return options
}

const authorizationServerMetadata: AuthorizationServerMetadata = {
  issuer: 'https://example.com',
  authorization_endpoint: 'https://example.com/authorize',
  token_endpoint: 'https://example.com/token',
  interactive_authorization_endpoint: 'https://example.com/interactive-authorization',
}

describe('Interactive Authorization Endpoint - Client', () => {
  test('should send initial interactive authorization request', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async (url, init) => {
          expect(url).toBe('https://example.com/interactive-authorization')
          expect(init?.method).toBe('POST')
          expect(init?.headers).toBeDefined()

          const body = new URLSearchParams(init?.body as string)
          expect(body.get('response_type')).toBe('code')
          expect(body.get('client_id')).toBe('test-client')
          expect(body.get('interaction_types_supported')).toBe('openid4vp_presentation,redirect_to_web')
          expect(body.get('redirect_uri')).toBe('https://example.com/callback')

          return new Response(
            JSON.stringify({
              status: 'require_interaction',
              type: 'openid4vp_presentation',
              auth_session: 'session-123',
              openid4vp_request: {
                request: 'eyJhbGc...',
                client_id: 'https://example.com',
              },
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation,redirect_to_web',
      redirect_uri: 'https://example.com/callback',
      scope: 'openid',
    }

    const result = await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
    })

    expect(result.response).toBeDefined()
    expect(result.response?.status).toBe('require_interaction')
    if (result.response?.status === 'require_interaction') {
      expect(result.response.type).toBe('openid4vp_presentation')
      expect(result.response.auth_session).toBe('session-123')
      expect(result.response.openid4vp_request).toBeDefined()
      expect((result.response.openid4vp_request as { request: string }).request).toBe('eyJhbGc...')
    }
  })

  test('should send follow-up interactive authorization request with openid4vp response', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async (url, init) => {
          expect(url).toBe('https://example.com/interactive-authorization')
          expect(init?.method).toBe('POST')

          const body = new URLSearchParams(init?.body as string)
          expect(body.get('auth_session')).toBe('session-123')
          expect(body.get('openid4vp_response')).toBeDefined()

          return new Response(
            JSON.stringify({
              status: 'ok',
              code: 'auth-code-456',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationFollowUpRequest = {
      auth_session: 'session-123',
      openid4vp_response: JSON.stringify({ vp_token: 'vp-token-data' }),
    }

    const result = await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
    })

    expect(result.response).toBeDefined()
    expect(result.response?.status).toBe('ok')
    if (result.response?.status === 'ok') {
      expect(result.response.code).toBe('auth-code-456')
    }
  })

  test('should send follow-up request with redirect_to_web (PKCE)', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async (_url, init) => {
          const body = new URLSearchParams(init?.body as string)
          expect(body.get('auth_session')).toBe('session-789')
          expect(body.get('code_verifier')).toBe('verifier-xyz')

          return new Response(
            JSON.stringify({
              status: 'ok',
              code: 'auth-code-789',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationFollowUpRequest = {
      auth_session: 'session-789',
      code_verifier: 'verifier-xyz',
    }

    const result = await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
    })

    expect(result.response).toBeDefined()
    expect(result.response?.status).toBe('ok')
    if (result.response?.status === 'ok') {
      expect(result.response.code).toBe('auth-code-789')
    }
  })

  test('should handle error response', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async () => {
          // Error responses should still be 200 OK with error in body
          return new Response(
            JSON.stringify({
              error: Oauth2ErrorCodes.InvalidRequest,
              error_description: 'Missing required parameter',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation',
    }

    const result = await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
    })

    expect(result.response).toBeDefined()
    if (result.response && 'error' in result.response) {
      expect(result.response.error).toBe(Oauth2ErrorCodes.InvalidRequest)
      expect(result.response.error_description).toBe('Missing required parameter')
    }
  })

  test('should handle redirect_to_web interaction type', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async () => {
          return new Response(
            JSON.stringify({
              status: 'require_interaction',
              type: 'redirect_to_web',
              auth_session: 'session-web-123',
              request_uri: 'urn:ietf:params:oauth:request_uri:abc123',
              expires_in: 600,
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'redirect_to_web',
      redirect_uri: 'https://example.com/callback',
    }

    const result = await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
    })

    expect(result.response).toBeDefined()
    expect(result.response?.status).toBe('require_interaction')
    if (result.response?.status === 'require_interaction') {
      expect(result.response.type).toBe('redirect_to_web')
      expect(result.response.auth_session).toBe('session-web-123')
      expect(result.response.request_uri).toBe('urn:ietf:params:oauth:request_uri:abc123')
      expect(result.response.expires_in).toBe(600)
    }
  })

  test('should throw error when interactive_authorization_endpoint is not supported', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async () => {
          throw new Error('Should not be called')
        },
      },
    })

    const metadataWithoutIAE: AuthorizationServerMetadata = {
      issuer: 'https://example.com',
      authorization_endpoint: 'https://example.com/authorize',
      token_endpoint: 'https://example.com/token',
    }

    const request: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation',
    }

    await expect(
      client.sendInteractiveAuthorizationRequest({
        authorizationServerMetadata: metadataWithoutIAE,
        request,
      })
    ).rejects.toThrow('interactive_authorization_endpoint')
  })

  test('should support DPoP binding', async () => {
    const keyPair = await generateJwkKeyPair()
    const dpopKeyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey, dpopKeyPair.privateKey])

    const dpopSigner = createJwtSigner({ method: 'jwk', alg: 'ES256', publicJwk: dpopKeyPair.publicKey })

    let dpopHeaderReceived = false

    const client = new Oauth2Client({
      callbacks: {
        ...callbacks,
        signJwt,
        fetch: async (_url, init) => {
          // Check if DPoP header is present
          const headers = init?.headers
          if (headers) {
            if (headers instanceof Headers) {
              if (headers.get('DPoP')) {
                dpopHeaderReceived = true
              }
            } else if (typeof headers === 'object' && 'DPoP' in headers) {
              dpopHeaderReceived = true
            }
          }

          return new Response(
            JSON.stringify({
              status: 'ok',
              code: 'auth-code-dpop',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }
          )
        },
      },
    })

    const request: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation',
    }

    await client.sendInteractiveAuthorizationRequest({
      authorizationServerMetadata,
      request,
      dpop: { signer: dpopSigner },
    })

    expect(dpopHeaderReceived).toBe(true)
  })
})

describe('Interactive Authorization Endpoint - Server', () => {
  test('should parse initial interactive authorization request', () => {
    const authServer = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const requestBody = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation,redirect_to_web',
      redirect_uri: 'https://example.com/callback',
      scope: 'openid',
    }

    const result = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: requestBody,
    })

    expect(result.isFollowUpRequest).toBe(false)
    expect(result.interactiveAuthorizationRequest).toEqual(requestBody)
  })

  test('should parse follow-up interactive authorization request', () => {
    const authServer = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const requestBody = {
      auth_session: 'session-123',
      openid4vp_response: JSON.stringify({ vp_token: 'vp-token-data' }),
    }

    const result = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: requestBody,
    })

    expect(result.isFollowUpRequest).toBe(true)
    expect(result.interactiveAuthorizationRequest).toMatchObject({
      auth_session: 'session-123',
      openid4vp_response: requestBody.openid4vp_response,
    })
  })

  test('should fail parsing when interaction_types_supported is missing', () => {
    const authServer = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const requestBody = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/callback',
    }

    expect(() =>
      authServer.parseInteractiveAuthorizationRequest({
        request: {
          url: 'https://example.com/interactive-authorization',
          method: 'POST',
          headers: new Headers({
            'content-type': 'application/x-www-form-urlencoded',
          }),
        },
        interactiveAuthorizationRequest: requestBody,
      })
    ).toThrow(Oauth2ServerErrorResponseError)
  })

  test('should verify initial interactive authorization request', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt,
      },
    })

    const requestBody: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation',
      redirect_uri: 'https://example.com/callback',
    }

    const result = await server.verifyInteractiveAuthorizationRequest({
      interactiveAuthorizationRequest: requestBody,
      isFollowUpRequest: false,
      authorizationServerMetadata,
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers(),
      },
    })

    expect(result).toBeDefined()
    expect(result.dpop).toBeUndefined()
    expect(result.clientAttestation).toBeUndefined()
  })

  test('should verify follow-up request (minimal verification)', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt,
      },
    })

    const requestBody: InteractiveAuthorizationFollowUpRequest = {
      auth_session: 'session-123',
      openid4vp_response: JSON.stringify({ vp_token: 'vp-token-data' }),
    }

    const result = await server.verifyInteractiveAuthorizationRequest({
      interactiveAuthorizationRequest: requestBody,
      isFollowUpRequest: true,
      authorizationServerMetadata,
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers(),
      },
    })

    expect(result).toBeDefined()
    expect(result.dpop).toBeUndefined()
    expect(result.clientAttestation).toBeUndefined()
  })

  test('should create authorization code response', () => {
    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const response = server.createInteractiveAuthorizationCodeResponse({
      authorizationCode: 'auth-code-123',
    })

    expect(response.status).toBe('ok')
    expect(response.code).toBe('auth-code-123')
  })

  test('should create openid4vp_presentation interaction response', () => {
    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const response = server.createInteractiveAuthorizationOpenid4vpInteraction({
      authSession: 'session-456',
      openid4vpRequest: {
        request: 'eyJhbGc...',
        client_id: 'https://example.com',
      },
    })

    expect(response.status).toBe('require_interaction')
    expect(response.type).toBe('openid4vp_presentation')
    expect(response.auth_session).toBe('session-456')
    expect(response.openid4vp_request).toEqual({
      request: 'eyJhbGc...',
      client_id: 'https://example.com',
    })
  })

  test('should create redirect_to_web interaction response', () => {
    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const response = server.createInteractiveAuthorizationRedirectToWebInteraction({
      authSession: 'session-789',
      requestUri: 'urn:ietf:params:oauth:request_uri:xyz',
      expiresIn: 600,
    })

    expect(response.status).toBe('require_interaction')
    expect(response.type).toBe('redirect_to_web')
    expect(response.auth_session).toBe('session-789')
    expect(response.request_uri).toBe('urn:ietf:params:oauth:request_uri:xyz')
    expect(response.expires_in).toBe(600)
  })

  test('should create error response', () => {
    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    const response = server.createInteractiveAuthorizationErrorResponse({
      error: Oauth2ErrorCodes.InvalidRequest,
      errorDescription: 'Invalid interaction type',
    })

    expect(response.error).toBe(Oauth2ErrorCodes.InvalidRequest)
    expect(response.error_description).toBe('Invalid interaction type')
  })

  test('should use Oauth2AuthorizationServer helper methods', () => {
    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([]),
      },
    })

    // Test parsing
    const parsed = server.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: {
        response_type: 'code',
        client_id: 'test-client',
        interaction_types_supported: 'openid4vp_presentation',
      },
    })

    expect(parsed.isFollowUpRequest).toBe(false)
    expect(parsed.interactiveAuthorizationRequest.client_id).toBe('test-client')

    // Test response creation
    const codeResponse = server.createInteractiveAuthorizationCodeResponse({
      authorizationCode: 'auth-code-test',
    })
    expect(codeResponse.status).toBe('ok')
    expect(codeResponse.code).toBe('auth-code-test')

    const interactionResponse = server.createInteractiveAuthorizationOpenid4vpInteraction({
      authSession: 'session-test',
      openid4vpRequest: {
        request: 'jwt-request',
      },
    })
    expect(interactionResponse.status).toBe('require_interaction')
    expect(interactionResponse.type).toBe('openid4vp_presentation')
    expect(interactionResponse.auth_session).toBe('session-test')

    const errorResponse = server.createInteractiveAuthorizationErrorResponse({
      error: Oauth2ErrorCodes.InvalidClient,
      errorDescription: 'Client not found',
    })
    expect(errorResponse.error).toBe(Oauth2ErrorCodes.InvalidClient)
    expect(errorResponse.error_description).toBe('Client not found')
  })

  test('should parse request with client attestation headers', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const server = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt,
      },
    })

    const requestBody: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'test-client',
      interaction_types_supported: 'openid4vp_presentation',
      redirect_uri: 'https://example.com/callback',
    }

    // Test that client attestation headers can be provided
    // The actual verification would happen in verifyInteractiveAuthorizationRequest
    const attestationJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpc3MiOiJodHRwczovL2F0dGVzdGF0aW9uLXByb3ZpZGVyLmNvbSIsInN1YiI6InRlc3QtY2xpZW50IiwiaWF0IjoxNjk1MDAwMDAwLCJleHAiOjE2OTUwMDM2MDB9.signature'
    const popJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbi1wb3Arand0In0.eyJpc3MiOiJ0ZXN0LWNsaWVudCIsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJpYXQiOjE2OTUwMDAwMDAsImV4cCI6MTY5NTAwMDMwMCwianRpIjoiYWJjMTIzIn0.signature'

    const parsed = server.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
          'oauth-client-attestation': attestationJwt,
          'oauth-client-attestation-pop': popJwt,
        }),
      },
      interactiveAuthorizationRequest: requestBody,
    })

    // Verify the request was parsed successfully
    expect(parsed.isFollowUpRequest).toBe(false)
    expect(parsed.interactiveAuthorizationRequest.client_id).toBe('test-client')

    // Client attestation extraction is handled by parseAuthorizationRequest
    // The attestation headers are available in the request for verification
    expect(parsed.clientAttestation).toBeDefined()
  })
})

describe('Interactive Authorization Endpoint - Integration', () => {
  test('should complete full openid4vp_presentation flow', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const authServer = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt,
      },
    })

    // Step 1: Client sends initial request
    const initialRequest: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'wallet-client',
      interaction_types_supported: 'openid4vp_presentation,redirect_to_web',
      redirect_uri: 'https://wallet.example.com/callback',
      authorization_details: [
        {
          type: 'openid_credential',
          format: 'vc+sd-jwt',
          vct: 'IdentityCredential',
        },
      ],
    }

    const parsed1 = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: initialRequest,
    })

    expect(parsed1.isFollowUpRequest).toBe(false)

    await authServer.verifyInteractiveAuthorizationRequest({
      interactiveAuthorizationRequest: parsed1.interactiveAuthorizationRequest,
      isFollowUpRequest: parsed1.isFollowUpRequest,
      authorizationServerMetadata,
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers(),
      },
    })

    // Step 2: Server responds with openid4vp_presentation interaction
    const interactionResponse = authServer.createInteractiveAuthorizationOpenid4vpInteraction({
      authSession: 'session-integration-123',
      openid4vpRequest: {
        request: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...',
        client_id: 'https://example.com',
      },
    })

    expect(interactionResponse.status).toBe('require_interaction')
    expect(interactionResponse.type).toBe('openid4vp_presentation')
    expect(interactionResponse.auth_session).toBe('session-integration-123')

    // Step 3: Client submits openid4vp response
    const followUpRequest: InteractiveAuthorizationFollowUpRequest = {
      auth_session: interactionResponse.auth_session,
      openid4vp_response: JSON.stringify({
        vp_token: 'eyJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUo5...',
        presentation_submission: {
          id: 'submission-1',
          definition_id: 'definition-1',
          descriptor_map: [],
        },
      }),
    }

    const parsed2 = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: followUpRequest,
    })

    expect(parsed2.isFollowUpRequest).toBe(true)

    await authServer.verifyInteractiveAuthorizationRequest({
      interactiveAuthorizationRequest: parsed2.interactiveAuthorizationRequest,
      isFollowUpRequest: parsed2.isFollowUpRequest,
      authorizationServerMetadata,
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers(),
      },
    })

    // Step 4: Server responds with authorization code
    const codeResponse = authServer.createInteractiveAuthorizationCodeResponse({
      authorizationCode: 'final-auth-code-xyz',
    })

    expect(codeResponse.status).toBe('ok')
    expect(codeResponse.code).toBe('final-auth-code-xyz')
  })

  test('should complete full redirect_to_web flow', async () => {
    const keyPair = await generateJwkKeyPair()
    const signJwt = getSignJwtCallback([keyPair.privateKey])

    const authServer = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks,
        signJwt,
      },
    })

    // Step 1: Client sends initial request
    const initialRequest: InteractiveAuthorizationRequest = {
      response_type: 'code',
      client_id: 'wallet-client',
      interaction_types_supported: 'redirect_to_web',
      redirect_uri: 'https://wallet.example.com/callback',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    }

    const parsed1 = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: initialRequest,
    })

    expect(parsed1.isFollowUpRequest).toBe(false)

    // Step 2: Server responds with redirect_to_web interaction
    const interactionResponse = authServer.createInteractiveAuthorizationRedirectToWebInteraction({
      authSession: 'session-web-456',
      requestUri: 'urn:ietf:params:oauth:request_uri:abc123',
      expiresIn: 600,
    })

    expect(interactionResponse.status).toBe('require_interaction')
    expect(interactionResponse.type).toBe('redirect_to_web')

    // Step 3: Client submits code_verifier after web interaction
    const followUpRequest: InteractiveAuthorizationFollowUpRequest = {
      auth_session: interactionResponse.auth_session,
      code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    }

    const parsed2 = authServer.parseInteractiveAuthorizationRequest({
      request: {
        url: 'https://example.com/interactive-authorization',
        method: 'POST',
        headers: new Headers({
          'content-type': 'application/x-www-form-urlencoded',
        }),
      },
      interactiveAuthorizationRequest: followUpRequest,
    })

    expect(parsed2.isFollowUpRequest).toBe(true)

    // Step 4: Server responds with authorization code
    const codeResponse = authServer.createInteractiveAuthorizationCodeResponse({
      authorizationCode: 'web-auth-code-789',
    })

    expect(codeResponse.status).toBe('ok')
    expect(codeResponse.code).toBe('web-auth-code-789')
  })
})
