import { zInteger } from '@openid4vc/utils'
import z from 'zod'
import { zJwtHeader, zJwtPayload } from '../common/jwt/z-jwt'

export const zIdTokenJwtHeader = z
  .object({
    ...zJwtHeader.shape,
  })
  .loose()
export type IdTokenJwtHeader = z.infer<typeof zIdTokenJwtHeader>

export const zIdTokenJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    iss: z.string(),
    sub: z.string(),
    aud: z.union([z.string(), z.array(z.string())]),
    exp: zInteger,
    iat: zInteger,
    auth_time: zInteger.optional(),
    acr: z.string().optional(),
    amr: z.array(z.string()).optional(),
    azp: z.string().optional(),

    // Standard Profile Claims
    // https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    name: z.string().optional(),
    given_name: z.string().optional(),
    family_name: z.string().optional(),
    middle_name: z.string().optional(),
    nickname: z.string().optional(),
    preferred_username: z.string().optional(),
    profile: z.url().optional(),
    picture: z.url().optional(),
    website: z.url().optional(),
    email: z.email().optional(),
    email_verified: z.boolean().optional(),
    gender: z.enum(['male', 'female']).or(z.string()).optional(),
    birthdate: z.iso.date().optional(),
    zoneinfo: z.string().optional(),
    locale: z.string().optional(),
    phone_number: z.string().optional(),
    phone_number_verified: z.boolean().optional(),
    address: z
      .object({
        formatted: z.string().optional(),
        street_address: z.string().optional(),
        locality: z.string().optional(),
        region: z.string().optional(),
        postal_code: z.string().optional(),
        country: z.string().optional(),
      })
      .loose()
      .optional(),
    updated_at: zInteger.optional(),
  })
  .loose()

export type IdTokenJwtPayload = z.infer<typeof zIdTokenJwtPayload>
