import type { MsoMdocFormatIdentifier } from './mso-mdoc/v-mso-mdoc'
import type { SdJwtVcFormatIdentifier } from './sd-jwt-vc/v-sd-jwt-vc'
import type { JwtVcJsonFormatIdentifier } from './w3c-vc/v-w3c-jwt-vc-json'
import type { JwtVcJsonLdFormatIdentifier } from './w3c-vc/v-w3c-jwt-vc-json-ld'
import type { LdpVcFormatIdentifier } from './w3c-vc/v-w3c-ldp-vc'

// mso_mdoc
export {
  type MsoMdocFormatIdentifier,
  vMsoMdocCredentialIssuerMetadata,
  vMsoMdocCredentialRequestFormat,
  vMsoMdocFormatIdentifier,
} from './mso-mdoc/v-mso-mdoc'

// vc+sd-jwt
export {
  type SdJwtVcFormatIdentifier,
  vSdJwtVcCredentialIssuerMetadata,
  vSdJwtVcCredentialRequestFormat,
  vSdJwtVcFormatIdentifier,
} from './sd-jwt-vc/v-sd-jwt-vc'

// ldp_vc
export {
  type LdpVcFormatIdentifier,
  vLdpVcCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadataDraft11,
  vLdpVcCredentialIssuerMetadataDraft11To14,
  vLdpVcCredentialIssuerMetadataDraft14To11,
  vLdpVcCredentialRequestFormat,
  vLdpVcCredentialRequestDraft14To11,
  vLdpVcFormatIdentifier,
} from './w3c-vc/v-w3c-ldp-vc'

// jwt_vc_json-ld
export {
  type JwtVcJsonLdFormatIdentifier,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadataDraft11,
  vJwtVcJsonLdCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonLdCredentialIssuerMetadataDraft14To11,
  vJwtVcJsonLdCredentialRequestFormat,
  vJwtVcJsonLdCredentialRequestDraft14To11,
  vJwtVcJsonLdFormatIdentifier,
} from './w3c-vc/v-w3c-jwt-vc-json-ld'

// jwt_vc_json
export {
  type JwtVcJsonFormatIdentifier,
  vJwtVcJsonCredentialIssuerMetadata,
  vJwtVcJsonCredentialIssuerMetadataDraft11,
  vJwtVcJsonCredentialIssuerMetadataDraft11To14,
  vJwtVcJsonCredentialIssuerMetadataDraft14To11,
  vJwtVcJsonCredentialRequestDraft14To11,
  vJwtVcJsonCredentialRequestFormat,
  vJwtVcJsonFormatIdentifier,
} from './w3c-vc/v-w3c-jwt-vc-json'

export type CredentialFormatIdentifier =
  | MsoMdocFormatIdentifier
  | SdJwtVcFormatIdentifier
  | LdpVcFormatIdentifier
  | JwtVcJsonLdFormatIdentifier
  | JwtVcJsonFormatIdentifier
