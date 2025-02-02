import type { MsoMdocFormatIdentifier } from './mso-mdoc/z-mso-mdoc'
import type { SdJwtVcFormatIdentifier } from './sd-jwt-vc/z-sd-jwt-vc'
import type { JwtVcJsonFormatIdentifier } from './w3c-vc/z-w3c-jwt-vc-json'
import type { JwtVcJsonLdFormatIdentifier } from './w3c-vc/z-w3c-jwt-vc-json-ld'
import type { LdpVcFormatIdentifier } from './w3c-vc/z-w3c-ldp-vc'

// mso_mdoc
export {
  type MsoMdocFormatIdentifier,
  zMsoMdocCredentialIssuerMetadata,
  zMsoMdocCredentialRequestFormat,
  zMsoMdocFormatIdentifier,
} from './mso-mdoc/z-mso-mdoc'

// vc+sd-jwt
export {
  type SdJwtVcFormatIdentifier,
  zSdJwtVcCredentialIssuerMetadata,
  zSdJwtVcCredentialRequestFormat,
  zSdJwtVcFormatIdentifier,
} from './sd-jwt-vc/z-sd-jwt-vc'

// ldp_vc
export {
  type LdpVcFormatIdentifier,
  zLdpVcCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadataDraft11,
  zLdpVcCredentialIssuerMetadataDraft11To14,
  zLdpVcCredentialIssuerMetadataDraft14To11,
  zLdpVcCredentialRequestFormat,
  zLdpVcCredentialRequestDraft14To11,
  zLdpVcFormatIdentifier,
} from './w3c-vc/z-w3c-ldp-vc'

// jwt_vc_json-ld
export {
  type JwtVcJsonLdFormatIdentifier,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadataDraft11,
  zJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonLdCredentialRequestFormat,
  zJwtVcJsonLdCredentialRequestDraft14To11,
  zJwtVcJsonLdFormatIdentifier,
} from './w3c-vc/z-w3c-jwt-vc-json-ld'

// jwt_vc_json
export {
  type JwtVcJsonFormatIdentifier,
  zJwtVcJsonCredentialIssuerMetadata,
  zJwtVcJsonCredentialIssuerMetadataDraft11,
  zJwtVcJsonCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonCredentialRequestDraft14To11,
  zJwtVcJsonCredentialRequestFormat,
  zJwtVcJsonFormatIdentifier,
} from './w3c-vc/z-w3c-jwt-vc-json'

export type CredentialFormatIdentifier =
  | MsoMdocFormatIdentifier
  | SdJwtVcFormatIdentifier
  | LdpVcFormatIdentifier
  | JwtVcJsonLdFormatIdentifier
  | JwtVcJsonFormatIdentifier
