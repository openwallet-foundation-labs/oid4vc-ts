// biome-ignore lint/style/useNodejsImportProtocol: also imported in other environments
import { Buffer } from 'buffer'

export function decodeUtf8String(string: string): Uint8Array {
  return new Uint8Array(Buffer.from(string, 'utf-8'))
}

export function encodeToUtf8String(data: Uint8Array) {
  return Buffer.from(data).toString('utf-8')
}

/**
 * Also supports base64 url
 */
export function decodeBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'))
}

export function encodeToBase64(data: Uint8Array | string) {
  // To make ts happy. Somehow Uint8Array or string is no bueno
  if (typeof data === 'string') {
    return Buffer.from(data).toString('base64')
  }

  return Buffer.from(data).toString('base64')
}

export function encodeToBase64Url(data: Uint8Array | string) {
  return base64ToBase64Url(encodeToBase64(data))
}

/**
 * The 'buffer' npm library does not support base64url.
 */
function base64ToBase64Url(base64: string) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

export function uriEncodeObject(obj: Record<string, unknown>) {
  return Object.entries(obj)
    .map(
      ([key, val]) =>
        `${key}=${encodeURIComponent(
          typeof val === 'string' || typeof val === 'boolean' || typeof val === 'number'
            ? val
            : encodeURIComponent(JSON.stringify(val as Record<string, unknown>))
        )}`
    )
    .join('&')
}
