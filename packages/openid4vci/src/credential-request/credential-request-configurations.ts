import { arrayEqualsIgnoreOrder } from '@openid4vc/utils'
import type { CredentialConfigurationsSupportedWithFormats } from '../metadata/credential-issuer/z-credential-issuer-metadata'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import type { CredentialRequestFormatSpecific } from './z-credential-request'

export interface GetCredentialConfigurationsMatchingRequestFormatOptions {
  requestFormat: CredentialRequestFormatSpecific
  issuerMetadata: IssuerMetadataResult
}

export function getCredentialConfigurationsMatchingRequestFormat({
  requestFormat,
  issuerMetadata,
}: GetCredentialConfigurationsMatchingRequestFormatOptions): CredentialConfigurationsSupportedWithFormats {
  // credential request format will only contain known formats
  const knownCredentialConfigurations = issuerMetadata.knownCredentialConfigurations

  return Object.fromEntries(
    Object.entries(knownCredentialConfigurations).filter(([, credentialConfiguration]) => {
      // Special case to handle vc+sd-jwt to dc+sd-jwt change
      const isSpecialVcToDcSdJwt =
        credentialConfiguration.format === 'dc+sd-jwt' && requestFormat.format === 'vc+sd-jwt'
      // NOTE: ideally we also check for the draft version fo the original issuer metadata
      // but in case you support multiple draft versions as issuer the original version will be 1.0
      // even though you have backwards support for e.g. Draft 11. If we want to check this we would need
      // to have a min/max version, like we have for OpenID4VP. So for now we just allow requests with formats
      // vc+sd-jwt even if the metadata only contains dc+sd-jwt. You can easily handle it on a higher level
      // if you don't want to support this multi-draft support.
      // [Openid4vciVersion.Draft11, Openid4vciVersion.Draft14].includes(issuerMetadata.originalDraftVersion)

      if (credentialConfiguration.format !== requestFormat.format && !isSpecialVcToDcSdJwt) return false

      const r = requestFormat
      const c = credentialConfiguration

      if ((c.format === 'ldp_vc' || c.format === 'jwt_vc_json-ld') && r.format === c.format) {
        return (
          arrayEqualsIgnoreOrder(r.credential_definition.type, c.credential_definition.type) &&
          arrayEqualsIgnoreOrder(r.credential_definition['@context'], c.credential_definition['@context'])
        )
      }

      if (c.format === 'jwt_vc_json' && r.format === c.format) {
        return arrayEqualsIgnoreOrder(r.credential_definition.type, c.credential_definition.type)
      }

      if (r.format === 'vc+sd-jwt' && (c.format === 'vc+sd-jwt' || c.format === 'dc+sd-jwt')) {
        if (r.vct && c.vct) {
          return r.vct === c.vct
        }

        if (c.format === 'vc+sd-jwt' && c.credential_definition && r.credential_definition) {
          return arrayEqualsIgnoreOrder(r.credential_definition.type, c.credential_definition.type)
        }
      }

      if (c.format === 'mso_mdoc' && r.format === c.format) {
        return r.doctype === c.doctype
      }

      return false
    })
  )
}
