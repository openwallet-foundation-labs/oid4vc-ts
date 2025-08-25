import { zIs } from '@openid4vc/utils'
import { Openid4vciError } from '../error/Openid4vciError'
import {
  zJwtVcJsonCredentialIssuerMetadata,
  zJwtVcJsonCredentialIssuerMetadataDraft14,
  zJwtVcJsonLdCredentialIssuerMetadata,
  zJwtVcJsonLdCredentialIssuerMetadataDraft14,
  zLdpVcCredentialIssuerMetadata,
  zLdpVcCredentialIssuerMetadataDraft14,
  zMsoMdocCredentialIssuerMetadata,
  zMsoMdocCredentialIssuerMetadataDraft14,
  zSdJwtDcCredentialIssuerMetadata,
  zSdJwtVcCredentialIssuerMetadataDraft14,
  zSdJwtVcFormatIdentifier,
} from '../formats/credential'
import { zSdJwtVcCredentialIssuerMetadataDraft16 } from '../formats/credential/sd-jwt-vc/z-sd-jwt-vc'
import { zSdJwtW3VcCredentialIssuerMetadata } from '../formats/credential/w3c-vc/z-w3c-sd-jwt-vc'
import { getCredentialConfigurationSupportedById } from '../metadata/credential-issuer/credential-issuer-metadata'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import type { CredentialRequestWithFormats } from './z-credential-request'

export interface GetCredentialRequestFormatPayloadForCredentialConfigurationIdOptions {
  /**
   * The credential configuration id to get the format payload for
   */
  credentialConfigurationId: string

  /**
   * Metadata of the credential issuer and authorization servers.
   */
  issuerMetadata: IssuerMetadataResult
}

export function getCredentialRequestFormatPayloadForCredentialConfigurationId(
  options: GetCredentialRequestFormatPayloadForCredentialConfigurationIdOptions
): CredentialRequestWithFormats {
  const credentialConfiguration = getCredentialConfigurationSupportedById(
    options.issuerMetadata.credentialIssuer.credential_configurations_supported,
    options.credentialConfigurationId
  )

  if (
    zIs(zSdJwtVcCredentialIssuerMetadataDraft16, credentialConfiguration) ||
    zIs(zSdJwtVcCredentialIssuerMetadataDraft14, credentialConfiguration)
  ) {
    return {
      format: credentialConfiguration.format,
      vct: credentialConfiguration.vct,
    }
  }

  if (
    zIs(zMsoMdocCredentialIssuerMetadata, credentialConfiguration) ||
    zIs(zMsoMdocCredentialIssuerMetadataDraft14, credentialConfiguration)
  ) {
    return {
      format: credentialConfiguration.format,
      doctype: credentialConfiguration.doctype,
    }
  }

  if (
    zIs(zLdpVcCredentialIssuerMetadata, credentialConfiguration) ||
    zIs(zLdpVcCredentialIssuerMetadataDraft14, credentialConfiguration)
  ) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (
    zIs(zJwtVcJsonLdCredentialIssuerMetadata, credentialConfiguration) ||
    zIs(zJwtVcJsonLdCredentialIssuerMetadataDraft14, credentialConfiguration)
  ) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (
    zIs(zJwtVcJsonCredentialIssuerMetadata, credentialConfiguration) ||
    zIs(zJwtVcJsonCredentialIssuerMetadataDraft14, credentialConfiguration)
  ) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (zIs(zSdJwtDcCredentialIssuerMetadata, credentialConfiguration)) {
    throw new Openid4vciError(
      `Credential configuration id '${options.credentialConfigurationId}' with format ${zSdJwtVcFormatIdentifier.value} does not support credential request based on 'format'. Use 'credential_configuration_id' directly.`
    )
  }

  if (zIs(zSdJwtW3VcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  throw new Openid4vciError(
    `Unknown format '${credentialConfiguration.format}' in credential configuration with id '${options.credentialConfigurationId}' for credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
  )
}
