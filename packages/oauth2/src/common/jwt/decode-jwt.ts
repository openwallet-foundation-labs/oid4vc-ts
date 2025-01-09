import type * as v from 'valibot'

import {
  type BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from '@openid4vc/utils'
import { Oauth2JwtParseError } from '../../error/Oauth2JwtParseError'
import { type JwtSigner, vJwtHeader, vJwtPayload } from './v-jwt'

export interface DecodeJwtOptions<
  HeaderSchema extends BaseSchema | undefined,
  PayloadSchema extends BaseSchema | undefined,
> {
  /**
   * The comapct encoded jwt
   */
  jwt: string

  /**
   * Schema to use for validating the header. If not provided the
   * default `vJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema

  /**
   * Schema to use for validating the payload. If not provided the
   * default `vJwtPayload` schema will be used
   */
  payloadSchema?: PayloadSchema
}

export type DecodeJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> = {
  header: InferSchemaOutput<HeaderSchema, typeof vJwtHeader>
  payload: InferSchemaOutput<PayloadSchema, typeof vJwtPayload>
  signature: string
}

export function decodeJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(options: DecodeJwtOptions<HeaderSchema, PayloadSchema>): DecodeJwtResult<HeaderSchema, PayloadSchema> {
  const jwtParts = options.jwt.split('.')
  if (jwtParts.length !== 3) {
    throw new Oauth2JwtParseError('Jwt is not a valid jwt, unable to decode')
  }

  let headerJson: Record<string, unknown>
  let payloadJson: Record<string, unknown>
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(jwtParts[0])),
      'Unable to parse jwt header to JSON'
    )
    payloadJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(jwtParts[1])),
      'Unable to parse jwt payload to JSON'
    )
  } catch (error) {
    throw new Oauth2JwtParseError('Error parsing JWT')
  }

  const header = parseWithErrorHandling(options.headerSchema ?? vJwtHeader, headerJson)
  const payload = parseWithErrorHandling(options.payloadSchema ?? vJwtPayload, payloadJson)

  return {
    header,
    payload,
    signature: jwtParts[2],
  }
}

export function jwtHeaderFromJwtSigner(signer: JwtSigner) {
  if (signer.method === 'did') {
    return {
      alg: signer.alg,
      kid: signer.didUrl,
    } as const
  }

  if (signer.method === 'trustChain') {
    return {
      alg: signer.alg,
      kid: signer.kid,
      trust_chain: signer.trustChain,
    } as const
  }

  if (signer.method === 'jwk') {
    return {
      alg: signer.alg,
      jwk: signer.publicJwk,
      kid: signer.publicJwk.kid,
    } as const
  }

  if (signer.method === 'x5c') {
    return {
      alg: signer.alg,
      x5c: signer.x5c,
    } as const
  }

  return {
    alg: signer.alg,
  }
}

export function jwtSignerFromJwt({ header, payload }: Pick<DecodeJwtResult, 'header' | 'payload'>): JwtSigner {
  if (header.x5c) {
    return {
      alg: header.alg,
      method: 'x5c',
      x5c: header.x5c,
    }
  }

  if (header.trust_chain) {
    if (!header.kid) {
      throw new Error(`When 'trust_chain' is used in jwt header, the 'kid' parameter is required.`)
    }

    return {
      method: 'trustChain',
      alg: header.alg,
      trustChain: header.trust_chain,
      kid: header.kid,
    }
  }

  if (header.kid) {
    if (header.kid.startsWith('did:')) {
      if (payload.iss && header.kid.startsWith(payload.iss)) {
      }

      if (!header.kid.includes('#')) {
      }

      return {
        method: 'did',
        didUrl: header.kid,
        alg: header.alg,
      }
    }

    if (header.kid.startsWith('#') && payload.iss?.startsWith('did:')) {
      return {
        method: 'did',
        didUrl: `${payload.iss}${header.kid}`,
        alg: header.alg,
      }
    }
  }

  if (header.jwk) {
    return {
      alg: header.alg,
      method: 'jwk',
      publicJwk: header.jwk,
    }
  }

  return {
    method: 'custom',
    alg: header.alg,
  }
}

// Helper type to check if a schema is provided
type IsSchemaProvided<T> = T extends undefined ? false : true

// Helper type to infer the output type based on whether a schema is provided
type InferSchemaOutput<
  ProvidedSchema extends BaseSchema | undefined,
  DefaultSchema extends BaseSchema,
> = IsSchemaProvided<ProvidedSchema> extends true
  ? ProvidedSchema extends BaseSchema
    ? v.InferOutput<ProvidedSchema>
    : never
  : v.InferOutput<DefaultSchema>
