import type * as v from 'valibot'
import { Oid4vcError } from '../../error/Oid4vcError'
import { decodeBase64, encodeToUtf8String } from '../encoding'
import { parseWithErrorHandling, stringToJsonWithErrorHandling } from '../validation/parse'
import type { BaseSchema } from '../validation/v-common'
import { vJwtHeader, vJwtPayload } from './v-jwt'

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

export function decodeJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(options: DecodeJwtOptions<HeaderSchema, PayloadSchema>) {
  const jwtParts = options.jwt.split('.')
  if (jwtParts.length !== 3) {
    throw new Oid4vcError('Jwt is not a valid jwt, unable to decode')
  }

  const headerJson = stringToJsonWithErrorHandling(
    encodeToUtf8String(decodeBase64(jwtParts[0])),
    'Unable to parse jwt header to JSON'
  )
  const payloadJson = stringToJsonWithErrorHandling(
    encodeToUtf8String(decodeBase64(jwtParts[1])),
    'Unable to parse jwt payload to JSON'
  )

  const header = parseWithErrorHandling(options.headerSchema ?? vJwtHeader, headerJson)
  const payload = parseWithErrorHandling(options.payloadSchema ?? vJwtPayload, payloadJson)

  return {
    header: header as InferSchemaOutput<HeaderSchema, typeof vJwtHeader>,
    payload: payload as InferSchemaOutput<PayloadSchema, typeof vJwtPayload>,
    signature: jwtParts[2],
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
