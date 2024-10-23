export class Oid4vcJsonParseError extends Error {
  public constructor(message: string, jsonString: string) {
    super(`${message}\n${jsonString}`)
  }
}
