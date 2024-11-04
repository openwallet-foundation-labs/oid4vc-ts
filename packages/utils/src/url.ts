import { URL, URLSearchParams } from './globals'

export function getQueryParams(url: string) {
  const parsedUrl = new URL(url)
  const searchParams = new URLSearchParams(parsedUrl.search)
  const params: Record<string, string> = {}

  searchParams.forEach((value, key) => {
    params[key] = value
  })

  return params
}

export function objectToQueryParams(object: Record<string, unknown>): InstanceType<typeof URLSearchParams> {
  const params = new URLSearchParams()

  for (const [key, value] of Object.entries(object)) {
    if (value != null) {
      params.append(key, typeof value === 'object' ? JSON.stringify(value) : String(value))
    }
  }

  return params
}
