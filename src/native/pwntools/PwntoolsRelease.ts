/** Verified unchanged upstream profile for the Linux ELF adapter. */
export const PWNTOOLS_PROVIDER_IDENTITY = {
  id: "pwntools-elf",
  name: "REA pwntools ELF adapter",
  version: "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2",
} as const;
/** Complete evidence budgets; address-space is separate from resident memory. */
export const PWNTOOLS_LIMITS = {
  inputBytes: 32 * 1024 * 1024,
  outputBytes: 64 * 1024 * 1024,
  diagnosticBytes: 1024 * 1024,
  timeoutMs: 30_000,
} as const;
