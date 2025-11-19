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
      if (credentialConfiguration.format !== requestFormat.format) return false

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

      if (c.format === 'vc+sd-jwt' && r.format === c.format) {
        if (r.vct && c.vct) {
          return r.vct === c.vct
        }

        if (c.credential_definition && r.credential_definition) {
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
