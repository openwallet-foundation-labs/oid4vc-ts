export function xWwwFormUrlEncodeObject(object: Record<string, unknown>) {
  return Object.entries(object)
    .map(([key, value]) => {
      if (value === null || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'undefined') {
        throw new Error(`Invalid value type for key: ${key}`)
      }

      const stringifiedValue = typeof value === 'object' ? JSON.stringify(value) : String(value)

      return `${encodeURIComponent(key)}=${encodeURIComponent(stringifiedValue)}`
    })
    .join('&')
}
