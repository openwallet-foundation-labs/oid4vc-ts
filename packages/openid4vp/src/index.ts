export {
  getOpenid4vpClientId,
  type GetOpenid4vpClientIdOptions,
} from './client-identifier-prefix/parse-client-identifier-prefix'
export { zClientIdPrefix, type ClientIdPrefix } from './client-identifier-prefix/z-client-id-prefix'
export {
  verifyJarmAuthorizationResponse,
  type VerifyJarmAuthorizationResponseOptions,
  JarmMode,
} from './jarm/jarm-authorization-response/verify-jarm-authorization-response'
export { zJarmClientMetadata, type JarmClientMetadata } from './jarm/metadata/z-jarm-client-metadata'

export { type Openid4vpVersionNumber, parseAuthorizationRequestVersion } from './version'
export {
  createOpenid4vpAuthorizationRequest,
  type CreateOpenid4vpAuthorizationRequestOptions,
} from './authorization-request/create-authorization-request'
export {
  parseOpenid4vpAuthorizationRequest,
  type ParseOpenid4vpAuthorizationRequestOptions,
} from './authorization-request/parse-authorization-request-params'
export {
  resolveOpenid4vpAuthorizationRequest,
  type ResolveOpenid4vpAuthorizationRequestOptions,
  type ResolvedOpenid4vpAuthorizationRequest,
} from './authorization-request/resolve-authorization-request'
export type { Openid4vpAuthorizationRequest } from './authorization-request/z-authorization-request'
export {
  validateOpenid4vpAuthorizationRequestPayload,
  type ValidateOpenid4vpAuthorizationRequestPayloadOptions,
  type WalletVerificationOptions,
} from './authorization-request/validate-authorization-request'
export {
  createOpenid4vpAuthorizationResponse,
  type CreateOpenid4vpAuthorizationResponseOptions,
  type CreateOpenid4vpAuthorizationResponseResult,
} from './authorization-response/create-authorization-response'
export {
  submitOpenid4vpAuthorizationResponse,
  type SubmitOpenid4vpAuthorizationResponseOptions,
} from './authorization-response/submit-authorization-response'
export {
  validateOpenid4vpAuthorizationResponsePayload,
  type ValidateOpenid4vpAuthorizationResponseOptions,
} from './authorization-response/validate-authorization-response'
export {
  parseTransactionData,
  type ParseTransactionDataOptions,
} from './transaction-data/parse-transaction-data'
export type { TransactionDataEntry } from './transaction-data/z-transaction-data'
export type {
  TransactionDataHashesCredentials,
  VerifiedTransactionDataEntry,
  VerifyTransactionDataOptions,
} from './transaction-data/verify-transaction-data'
export {
  parsePexVpToken,
  parseDcqlVpToken,
} from './vp-token/parse-vp-token'
export type { VpToken, VpTokenDcql, VpTokenPex, VpTokenPresentationEntry } from './vp-token/z-vp-token'

export {
  parseOpenid4vpAuthorizationResponse,
  type ParseOpenid4vpAuthorizationResponseOptions,
  type ParsedOpenid4vpAuthorizationResponse,
} from './authorization-response/parse-authorization-response'

export { parseOpenid4VpAuthorizationResponsePayload } from './authorization-response/parse-authorization-response-payload'

export {
  parseJarmAuthorizationResponse,
  type ParseJarmAuthorizationResponseOptions,
} from './authorization-response/parse-jarm-authorization-response'

export type {
  ValidateOpenid4VpPexAuthorizationResponseResult,
  ValidateOpenid4VpDcqlAuthorizationResponseResult,
  ValidateOpenid4VpAuthorizationResponseResult,
} from './authorization-response/validate-authorization-response-result'

export { Openid4vpClient } from './Openid4vpClient'
export { Openid4vpVerifier } from './Openid4vpVerifier'
export {
  zOpenid4vpAuthorizationResponse,
  type Openid4vpAuthorizationResponse,
} from './authorization-response/z-authorization-response'

export { isJarmResponseMode } from './jarm/jarm-response-mode'
export { extractEncryptionJwkFromJwks } from './jarm/jarm-extract-jwks'

export {
  isOpenid4vpAuthorizationRequestDcApi,
  type Openid4vpAuthorizationRequestDcApi,
} from './authorization-request/z-authorization-request-dc-api'

export {
  zClientMetadata,
  type ClientMetadata,
} from './models/z-client-metadata'

export {
  zCredentialFormat,
  type CredentialFormat,
} from './models/z-credential-formats'

export {
  zProofFormat,
  type ProofFormat,
} from './models/z-proof-formats'

export {
  zWalletMetadata,
  type WalletMetadata,
} from './models/z-wallet-metadata'

export {
  zVerifierAttestations,
  type VerifierAttestation,
  type VerifierAttestations,
} from './models/z-verifier-attestations'
