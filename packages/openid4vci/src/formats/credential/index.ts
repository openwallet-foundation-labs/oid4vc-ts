import type { MsoMdocFormatIdentifier } from './mso-mdoc/z-mso-mdoc'
import type { SdJwtDcFormatIdentifier } from './sd-jwt-dc/z-sd-jwt-dc'
import type { LegacySdJwtVcFormatIdentifier } from './sd-jwt-vc/z-sd-jwt-vc'
import type { JwtVcJsonFormatIdentifier } from './w3c-vc/z-w3c-jwt-vc-json'
import type { JwtVcJsonLdFormatIdentifier } from './w3c-vc/z-w3c-jwt-vc-json-ld'
import type { LdpVcFormatIdentifier } from './w3c-vc/z-w3c-ldp-vc'

// mso_mdoc
export {
  type MsoMdocFormatIdentifier,
  zMsoMdocCredentialIssuerMetadata,
  zMsoMdocCredentialIssuerMetadataDraft15,
  zMsoMdocCredentialIssuerMetadataDraft14,
  zMsoMdocCredentialRequestFormatDraft14,
  zMsoMdocFormatIdentifier,
} from './mso-mdoc/z-mso-mdoc'

// Legacy vc+sd-jwt
export {
  type LegacySdJwtVcFormatIdentifier,
  zLegacySdJwtVcCredentialIssuerMetadataDraft14,
  zLegacySdJwtVcCredentialRequestFormatDraft14,
  zLegacySdJwtVcFormatIdentifier,
} from './sd-jwt-vc/z-sd-jwt-vc'

// dc+sd-jwt
export {
  type SdJwtDcFormatIdentifier,
  zSdJwtDcCredentialIssuerMetadata,
  zSdJwtDcCredentialIssuerMetadataDraft15,
  zSdJwtDcFormatIdentifier,
} from './sd-jwt-dc/z-sd-jwt-dc'

// ldp_vc
export {
  type LdpVcFormatIdentifier,
  zLdpVcCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadataDraft15,
  zLdpVcCredentialIssuerMetadataDraft14,
  zLdpVcCredentialIssuerMetadataDraft11,
  zLdpVcCredentialIssuerMetadataDraft11To14,
  zLdpVcCredentialIssuerMetadataDraft14To11,
  zLdpVcCredentialRequestFormatDraft14,
  zLdpVcCredentialRequestDraft14To11,
  zLdpVcFormatIdentifier,
} from './w3c-vc/z-w3c-ldp-vc'

// jwt_vc_json-ld
export {
  type JwtVcJsonLdFormatIdentifier,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadataDraft15,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft11,
  zJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonLdCredentialRequestFormatDraft14,
  zJwtVcJsonLdCredentialRequestDraft14To11,
  zJwtVcJsonLdFormatIdentifier,
} from './w3c-vc/z-w3c-jwt-vc-json-ld'

// jwt_vc_json
export {
  type JwtVcJsonFormatIdentifier,
  zJwtVcJsonCredentialIssuerMetadata,
  zJwtVcJsonCredentialIssuerMetadataDraft15,
  zJwtVcJsonCredentialIssuerMetadataDraft14,
  zJwtVcJsonCredentialIssuerMetadataDraft11,
  zJwtVcJsonCredentialIssuerMetadataDraft11To14,
  zJwtVcJsonCredentialIssuerMetadataDraft14To11,
  zJwtVcJsonCredentialRequestDraft14To11,
  zJwtVcJsonCredentialRequestFormatDraft14,
  zJwtVcJsonFormatIdentifier,
} from './w3c-vc/z-w3c-jwt-vc-json'

// vc+sd-jwt
export {
  type SdJwtW3VcFormatIdentifier,
  zSdJwtW3VcCredentialIssuerMetadata,
  zSdJwtW3VcCredentialIssuerMetadataDraft15,
  zSdJwtW3VcCredentialRequestFormatDraft14,
  zSdJwtW3VcFormatIdentifier,
} from './w3c-vc/z-w3c-sd-jwt-vc'

export type CredentialFormatIdentifier =
  | MsoMdocFormatIdentifier
  | LegacySdJwtVcFormatIdentifier
  | SdJwtDcFormatIdentifier
  | LdpVcFormatIdentifier
  | JwtVcJsonLdFormatIdentifier
  | JwtVcJsonFormatIdentifier
