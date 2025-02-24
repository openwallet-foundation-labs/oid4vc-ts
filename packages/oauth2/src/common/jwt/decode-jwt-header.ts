import {
  type BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from '@openid4vc/utils'
import { Oauth2JwtParseError } from '../../error/Oauth2JwtParseError'
import type { InferSchemaOrDefaultOutput } from './decode-jwt'
import { zJwtHeader } from './z-jwt'

export interface DecodeJwtHeaderOptions<HeaderSchema extends BaseSchema | undefined> {
  /**
   * The comapct encoded jwt
   */
  jwt: string

  /**
   * Schema to use for validating the header. If not provided the
   * default `vJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema
}

export type DecodeJwtHeaderResult<HeaderSchema extends BaseSchema | undefined = undefined> = {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>
}

export function decodeJwtHeader<HeaderSchema extends BaseSchema | undefined = undefined>(
  options: DecodeJwtHeaderOptions<HeaderSchema>
): DecodeJwtHeaderResult<HeaderSchema> {
  const jwtParts = options.jwt.split('.')
  if (jwtParts.length <= 2) {
    throw new Oauth2JwtParseError('Jwt is not a valid jwt, unable to decode')
  }

  let headerJson: Record<string, unknown>
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(jwtParts[0])),
      'Unable to parse jwt header to JSON'
    )
  } catch (error) {
    throw new Oauth2JwtParseError(`Error parsing JWT. ${error instanceof Error ? error.message : ''}`)
  }

  const header = parseWithErrorHandling(options.headerSchema ?? zJwtHeader, headerJson) as InferSchemaOrDefaultOutput<
    HeaderSchema,
    typeof zJwtHeader
  >

  return {
    header,
  }
}
