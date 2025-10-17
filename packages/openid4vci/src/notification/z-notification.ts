import z from 'zod'

const zNotificationEvent = z.enum(['credential_accepted', 'credential_failure', 'credential_deleted'])
export type NotificationEvent = z.infer<typeof zNotificationEvent>

export const zNotificationRequest = z
  .object({
    notification_id: z.string(),
    event: zNotificationEvent,
    event_description: z.optional(z.string()),
  })
  .loose()

export type NotificationRequest = z.infer<typeof zNotificationRequest>

export const zNotificationErrorResponse = z
  .object({
    error: z.enum(['invalid_notification_id', 'invalid_notification_request']),
  })
  .loose()
export type NotificationErrorResponse = z.infer<typeof zNotificationErrorResponse>
