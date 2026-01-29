import { OpenId4VcBaseError } from './OpenId4VcBaseError'

export class JsonParseError extends OpenId4VcBaseError {
  public constructor(message: string, jsonString: string) {
    super(`${message}\n${jsonString}`)
  }
}
