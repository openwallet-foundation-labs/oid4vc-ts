import type { SendNotificationResponseNotOk } from '../notification/notification'
import { Openid4vciError } from './Openid4vciError'

export class Openid4vciSendNotificationError extends Openid4vciError {
  public constructor(
    message: string,
    public response: SendNotificationResponseNotOk
  ) {
    super(message)
  }
}
