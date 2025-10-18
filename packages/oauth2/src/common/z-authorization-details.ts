import z from 'zod'

export const zAuthorizationDetailsEntryBase = z.object({
  type: z.string(),

  locations: z.array(z.string()).optional(),
  actions: z.array(z.string()).optional(),
  datatypes: z.array(z.string()).optional(),
  identifier: z.string().optional(),
  privileges: z.array(z.string()).optional(),
})
