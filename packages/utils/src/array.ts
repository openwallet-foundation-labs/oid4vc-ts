/**
 * Only primitive types allowed
 * Must have not duplicate entries (will always return false in this case)
 */
export function arrayEqualsIgnoreOrder<Item extends string | number | boolean>(
  a: Array<Item>,
  b: Array<Item>
): boolean {
  if (new Set(a).size !== new Set(b).size) return false
  if (a.length !== b.length) return false

  return a.every((k) => b.includes(k))
}
