import { OpenId4VcError } from "./OpenId4VcError";

export class JsonParseError extends OpenId4VcError {
  public constructor(message: string, jsonString: string) {
    super(`${message}\n${jsonString}`)
  }
}
