// sum.test.js
import { expect, test } from 'vitest'
import { ALL } from '../index'

test('all should be 42', () => {
  expect(ALL).toBe(42)
})
