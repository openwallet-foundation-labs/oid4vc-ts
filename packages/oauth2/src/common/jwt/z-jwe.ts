import { z } from 'zod'

export const zCompactJwe = z
  .string()
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, {
    message: 'Not a valid compact jwe',
  })
