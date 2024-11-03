export class JsonParseError extends Error {
  public constructor(message: string, jsonString: string) {
    super(`${message}\n${jsonString}`)
  }
}
