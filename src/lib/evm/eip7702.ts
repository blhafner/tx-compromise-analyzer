/** EIP-7702 account-code designator: 0xef0100 || address (20 bytes) */
export const EIP7702_DESIGNATOR = "0xef0100"

export function parseEip7702Delegation(
  code: string | undefined | null
): string | undefined {
  if (!code || code === "0x") return undefined
  const normalized = code.toLowerCase()
  if (!normalized.startsWith(EIP7702_DESIGNATOR)) return undefined
  if (normalized.length < 48) return undefined
  return `0x${normalized.slice(8, 48)}`
}

export function isEip7702Type(
  type: string | number | undefined | null
): boolean {
  return type === 4 || type === "0x4" || type === "eip7702" || type === "4"
}
