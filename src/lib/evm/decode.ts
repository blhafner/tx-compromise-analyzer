export const SELECTORS: Record<string, string> = {
  "0xa9059cbb": "transfer",
  "0x23b872dd": "transferFrom",
  "0x095ea7b3": "approve",
  "0x39509351": "increaseAllowance",
  "0xa22cb465": "setApprovalForAll",
  "0xd505accf": "permit",
  "0x8f3cc4c1": "permit", // common variant
  "0x2b67b570": "permit2.permit",
  "0x87517c45": "permit2.approve",
  "0x12aa3caf": "swap", // 1inch style
  "0x3593564c": "execute", // universal router
  "0x5ae401dc": "multicall",
  "0xac9650d8": "multicall",
  "0x1f0464d1": "claim",
  "0x6a627842": "mint",
  "0x42842e0e": "safeTransferFrom",
  "0xb88d4fde": "safeTransferFrom",
  "0xf242432a": "safeTransferFrom1155",
  "0x2eb2c2d6": "safeBatchTransferFrom",
  "0x40c10f19": "mint",
  "0x4e71d92d": "claim",
  "0x70a08231": "balanceOf",
  "0xdd62ed3e": "allowance",
}

export const DRAINER_SELECTORS = new Set([
  "approve",
  "increaseAllowance",
  "setApprovalForAll",
  "permit",
  "permit2.permit",
  "permit2.approve",
  "multicall",
  "execute",
  "claim",
])

export const SRP_SELECTORS = new Set(["transfer", "native_transfer"])

export function decodeSelector(input: string | undefined | null): string {
  if (!input || input === "0x" || input.length < 10) {
    return "native_transfer"
  }
  const sel = input.slice(0, 10).toLowerCase()
  return SELECTORS[sel] ?? `unknown(${sel})`
}

export function isEmptyInput(input: string | undefined | null): boolean {
  return !input || input === "0x" || input.length <= 2
}

/** ERC-20 Transfer(address,address,uint256) */
export const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

/** Approval(address,address,uint256) */
export const APPROVAL_TOPIC =
  "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

/** ApprovalForAll(address,address,bool) */
export const APPROVAL_FOR_ALL_TOPIC =
  "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"

export function topicToAddress(topic: string | undefined): string | undefined {
  if (!topic || topic.length < 66) return undefined
  return `0x${topic.slice(26).toLowerCase()}`
}
