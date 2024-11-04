// Theses types are provided by the platform (so @types/node, @types/react-native, DOM)

// biome-ignore lint/style/noRestrictedGlobals: <explanation>
const _URL = URL
// biome-ignore lint/style/noRestrictedGlobals: <explanation>
const _URLSearchParams = URLSearchParams

// biome-ignore lint/style/noRestrictedGlobals: <explanation>
export type Fetch = typeof fetch
// biome-ignore lint/style/noRestrictedGlobals: <explanation>
export type FetchResponse = Response
// biome-ignore lint/style/noRestrictedGlobals: <explanation>
const _Headers = Headers
export type FetchHeaders = globalThis.Headers

export { _URLSearchParams as URLSearchParams, _URL as URL, _Headers as Headers }
