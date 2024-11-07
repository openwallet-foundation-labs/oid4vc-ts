export interface Oid4vcTsConfig {
  /**
   * Whether to allow insecure http urls.
   *
   * @default false
   */
  allowInsecureUrls: boolean
}

let GLOBAL_CONFIG: Oid4vcTsConfig = {
  allowInsecureUrls: false,
}

export function setGlobalConfig(config: Oid4vcTsConfig) {
  GLOBAL_CONFIG = config
}

export function getGlobalConfig(): Oid4vcTsConfig {
  return GLOBAL_CONFIG
}
