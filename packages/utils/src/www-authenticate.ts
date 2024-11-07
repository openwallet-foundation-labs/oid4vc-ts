const unquote = (value: string) => value.substring(1, value.length - 1).replace(/\\"/g, '"')
// Fixup quoted strings and tokens with spaces around them
const sanitize = (value: string) => (value.charAt(0) === '"' ? unquote(value) : value.trim())

// lol dis
const body =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: <explanation>
  /((?:[a-zA-Z0-9._~+\/-]+=*(?:\s+|$))|[^\u0000-\u001F\u007F()<>@,;:\\"/?={}\[\]\u0020\u0009]+)(?:=([^\\"=\s,]+|"(?:[^"\\]|\\.)*"))?/g

export interface WwwAuthenticateHeaderChallenge {
  scheme: string

  /**
   * Record where the keys are the names, and the value can be 0 (null), 1 (string) or multiple (string[])
   * entries
   */
  payload: Record<string, string | string[] | null>
}

const parsePayload = (scheme: string, string: string): WwwAuthenticateHeaderChallenge => {
  const payload: Record<string, string | string[] | null> = {}

  while (true) {
    const res = body.exec(string)
    if (!res) break

    const [, key, newValue] = res

    const payloadValue = payload[key]
    if (newValue) {
      const sanitizedValue = sanitize(newValue)
      payload[key] = payloadValue
        ? Array.isArray(payloadValue)
          ? [...payloadValue, sanitizedValue]
          : [payloadValue, sanitizedValue]
        : sanitizedValue
    } else if (!payloadValue) {
      payload[key] = null
    }
  }

  return { scheme, payload }
}

export function parseWwwAuthenticateHeader(str: string): WwwAuthenticateHeaderChallenge[] {
  const start = str.indexOf(' ')
  let scheme = str.substring(0, start)
  let value = str.substring(start)

  const challenges: WwwAuthenticateHeaderChallenge[] = []

  // Some well-known schemes to support-multi parsing
  const endsWithSchemeRegex = /, ?(Bearer|DPoP|Basic)$/
  const endsWithSchemeTest = endsWithSchemeRegex.exec(value)
  let endsWithScheme: string | undefined = undefined
  if (endsWithSchemeTest) {
    value = value.substring(0, value.length - endsWithSchemeTest[0].length)
    endsWithScheme = endsWithSchemeTest[1]
  }

  const additionalSchemesRegex = /(.*?)(, ?)(Bearer|DPoP|Basic)[, ]/
  let match = additionalSchemesRegex.exec(value)
  while (match) {
    challenges.push(parsePayload(scheme, match[1]))
    value = value.substring(match[0].length - 1)
    scheme = match[3]

    match = additionalSchemesRegex.exec(value)
  }
  challenges.push(parsePayload(scheme, value))
  if (endsWithScheme) {
    challenges.push({ scheme: endsWithScheme, payload: {} })
  }
  return challenges
}

export function encodeWwwAuthenticateHeader(challenges: WwwAuthenticateHeaderChallenge[]) {
  const entries: string[] = []

  for (const challenge of challenges) {
    // Encode each parameter according to RFC 7235
    const encodedParams = Object.entries(challenge.payload).flatMap(([key, value]) => {
      const encode = (s: string) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
      // Convert value to string and escape special characters
      if (Array.isArray(value)) {
        return value.map((v) => `${key}="${encode(v)}"`)
      }

      return value ? `${key}="${encode(value)}"` : key
    })

    entries.push(encodedParams.length === 0 ? challenge.scheme : `${challenge.scheme} ${encodedParams.join(', ')}`)
  }

  return entries.join(', ')
}
