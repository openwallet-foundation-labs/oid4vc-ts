import type { SendNotificationResponseNotOk } from '../notification/notification'
import { Oid4vciError } from './Oid4vciError'

export class Oid4vciSendNotificationError extends Oid4vciError {
  public constructor(
    message: string,
    public response: SendNotificationResponseNotOk
  ) {
    super(message)
  }
}
