import { Oauth2Error } from '@animo-id/oauth2'
import * as v from 'valibot'
import {
  vJwtVcJsonCredentialIssuerMetadata,
  vJwtVcJsonLdCredentialIssuerMetadata,
  vLdpVcCredentialIssuerMetadata,
  vMsoMdocCredentialIssuerMetadata,
  vSdJwtVcCredentialIssuerMetadata,
} from '../formats/credential'
import type { IssuerMetadataResult } from '../metadata/fetch-issuer-metadata'
import type { CredentialRequestWithFormats } from './v-credential-request'

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
  const credentialConfiguration =
    options.issuerMetadata.credentialIssuer.credential_configurations_supported[options.credentialConfigurationId]

  if (!credentialConfiguration) {
    throw new Oauth2Error(
      `Could not find credential configuration with id '${options.credentialConfigurationId}' in metadata of credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'.`
    )
  }

  if (v.is(vSdJwtVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      vct: credentialConfiguration.vct,
    }
  }

  if (v.is(vMsoMdocCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      doctype: credentialConfiguration.doctype,
    }
  }

  if (v.is(vLdpVcCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (v.is(vJwtVcJsonLdCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        '@context': credentialConfiguration.credential_definition['@context'],
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  if (v.is(vJwtVcJsonCredentialIssuerMetadata, credentialConfiguration)) {
    return {
      format: credentialConfiguration.format,
      credential_definition: {
        type: credentialConfiguration.credential_definition.type,
      },
    }
  }

  throw new Oauth2Error(
    `Unknown format '${credentialConfiguration.format}' in credential configuration with id '${options.credentialConfigurationId}' for credential issuer '${options.issuerMetadata.credentialIssuer.credential_issuer}'`
  )
}
