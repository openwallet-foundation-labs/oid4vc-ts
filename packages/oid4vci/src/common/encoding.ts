// biome-ignore lint/style/useNodejsImportProtocol: also imported in other environments
import { Buffer } from 'buffer'

export function decodeUtf8StringToUint8Array(string: string) {
  return new Uint8Array(Buffer.from(string, 'utf-8').buffer)
}

export function encodeUint8ArrayToBase64(uint8Array: Uint8Array) {
  return Buffer.from(uint8Array).toString('base64')
}

export function encodeUint8ArrayToBase64Url(uint8Array: Uint8Array) {
  const base64 = encodeUint8ArrayToBase64(uint8Array)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
