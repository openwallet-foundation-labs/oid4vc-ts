import {
  type BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from '@openid4vc/utils'
import type z from 'zod'
import { Oauth2Error } from '../../error/Oauth2Error'
import { Oauth2JwtParseError } from '../../error/Oauth2JwtParseError'
import { decodeJwtHeader } from './decode-jwt-header'
import { type JwtSigner, type zJwtHeader, zJwtPayload } from './z-jwt'
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
   * default `zJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema

  /**
   * Schema to use for validating the payload. If not provided the
   * default `zJwtPayload` schema will be used
   */
  payloadSchema?: PayloadSchema
}

export type DecodeJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> = {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>
  payload: InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>
  signature: string
  compact: string
}

export function decodeJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(options: DecodeJwtOptions<HeaderSchema, PayloadSchema>): DecodeJwtResult<HeaderSchema, PayloadSchema> {
  const jwtParts = options.jwt.split('.')
  if (jwtParts.length !== 3) {
    throw new Oauth2JwtParseError('Jwt is not a valid jwt, unable to decode')
  }

  let payloadJson: Record<string, unknown>
  try {
    payloadJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(jwtParts[1])),
      'Unable to parse jwt payload to JSON'
    )
  } catch (error) {
    throw new Oauth2JwtParseError(`Error parsing JWT. ${error instanceof Error ? error.message : ''}`)
  }

  const { header } = decodeJwtHeader({ jwt: options.jwt, headerSchema: options.headerSchema })
  const payload = parseWithErrorHandling(options.payloadSchema ?? zJwtPayload, payloadJson)

  return {
    header: header as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>,
    payload: payload as InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>,
    signature: jwtParts[2],
    compact: options.jwt,
  }
}

export function jwtHeaderFromJwtSigner(signer: JwtSigner) {
  if (signer.method === 'did') {
    return {
      alg: signer.alg,
      kid: signer.didUrl,
    } as const
  }

  if (signer.method === 'federation') {
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

export function jwtSignerFromJwt({
  header,
  payload,
  allowedSignerMethods,
}: Pick<DecodeJwtResult, 'header' | 'payload'> & { allowedSignerMethods?: JwtSigner['method'][] }): JwtSigner {
  const found: Array<
    | { method: JwtSigner['method']; signer: JwtSigner; valid: true }
    | { method: JwtSigner['method']; error: string; valid: false }
  > = []

  if (header.x5c) {
    found.push({
      method: 'x5c',
      valid: true,
      signer: {
        alg: header.alg,
        method: 'x5c',
        x5c: header.x5c,
        kid: header.kid,
      },
    })
  }

  if (header.trust_chain) {
    if (!header.kid) {
      found.push({
        method: 'federation',
        valid: false,
        error: `When 'trust_chain' is used in jwt header, the 'kid' parameter is required.`,
      })
    } else {
      found.push({
        method: 'federation',
        valid: true,
        signer: {
          alg: header.alg,
          trustChain: header.trust_chain,
          kid: header.kid,
          method: 'federation',
        },
      })
    }
  }

  if (header.kid?.startsWith('did:') || payload.iss?.startsWith('did:')) {
    // NOTE: special exclusion for openid4vci-proof+jwt type as it requires the `iss` to be set to the `client_id` in case
    // of authorization code flow.
    if (
      payload.iss &&
      header.kid?.startsWith('did:') &&
      !header.kid.startsWith(payload.iss) &&
      header.typ !== 'openid4vci-proof+jwt'
    ) {
      found.push({
        method: 'did',
        valid: false,
        error: `kid in header starts with did that is different from did value in 'iss'`,
      })
    } else if (!header.kid?.startsWith('did:') && !header.kid?.startsWith('#')) {
      found.push({
        method: 'did',
        valid: false,
        error: `kid in header must start with either 'did:' or '#' when 'iss' value is a did`,
      })
    } else {
      found.push({
        method: 'did',
        valid: true,
        signer: {
          method: 'did',
          alg: header.alg,
          didUrl: header.kid.startsWith('did:') ? header.kid : `${payload.iss}${header.kid}`,
        },
      })
    }
  }

  if (header.jwk) {
    found.push({
      method: 'jwk',
      signer: { alg: header.alg, method: 'jwk', publicJwk: header.jwk },
      valid: true,
    })
  }

  const allowedFoundMethods = found.filter((f) => !allowedSignerMethods || allowedSignerMethods?.includes(f.method))
  const allowedValidMethods = allowedFoundMethods.filter((f) => f.valid)

  if (allowedValidMethods.length > 0) {
    // We found a valid method
    return allowedValidMethods[0].signer
  }

  if (allowedFoundMethods.length > 0) {
    throw new Oauth2Error(
      `Unable to extract signer method from jwt. Found ${allowedFoundMethods.length} allowed signer method(s) but contained invalid configuration:\n${allowedFoundMethods.map((m) => (m.valid ? '' : `FAILED: method ${m.method} - ${m.error}`)).join('\n')}`
    )
  }

  // Found x5c, allowed jwk
  if (found.length > 0) {
    throw new Oauth2Error(
      `Unable to extract signer method from jwt. Found ${found.length} signer method(s) that are not allowed:\n${found.map((m) => (m.valid ? `SUCCEEDED: method ${m.method}` : `FAILED: method ${m.method} - ${m.error}`)).join('\n')}`
    )
  }

  if (!allowedSignerMethods || allowedSignerMethods.includes('custom')) {
    return {
      method: 'custom',
      alg: header.alg,
      kid: header.kid,
    }
  }

  throw new Oauth2Error(
    `Unable to extract signer method from jwt. Found no signer methods and 'custom' signer method is not allowed.`
  )
}

// Helper type to check if a schema is provided
type IsSchemaProvided<T> = T extends undefined ? false : true

// Helper type to infer the output type based on whether a schema is provided
export type InferSchemaOrDefaultOutput<
  ProvidedSchema extends BaseSchema | undefined,
  DefaultSchema extends BaseSchema,
> =
  IsSchemaProvided<ProvidedSchema> extends true
    ? ProvidedSchema extends BaseSchema
      ? z.infer<ProvidedSchema>
      : never
    : z.infer<DefaultSchema>
