import { URLSearchParams } from './globals'
export const uriEncodeObject = (obj: Record<string, unknown>) => {
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

export const uriDecodeObject = (encodedStr: string): Record<string, unknown> => {
  const params = new URLSearchParams(encodedStr)
  const result: Record<string, unknown> = {}

  params.forEach((value, key) => {
    try {
      // Try to parse as JSON first for objects and arrays
      result[key] = JSON.parse(decodeURIComponent(value))
    } catch {
      // If parsing fails, handle primitive types
      const decodedValue = decodeURIComponent(value)

      if (decodedValue === 'true') {
        result[key] = true
      } else if (decodedValue === 'false') {
        result[key] = false
      } else if (!Number.isNaN(Number(decodedValue))) {
        result[key] = Number(decodedValue)
      } else {
        result[key] = decodedValue
      }
    }
  })

  return result
}
