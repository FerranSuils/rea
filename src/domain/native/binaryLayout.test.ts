import { expect, it } from "vitest";
import { binaryLayoutSchema } from "./binaryLayout.js";

const report = () => ({
  artifact: { path: "/fixture.elf", sha256: "a".repeat(64), bytes: 128 },
  format: "elf",
  architecture: { machine: "EM_X86_64", bits: 64, byte_order: "little" },
  image_type: "ET_EXEC",
  entry_point: {
    reported_value: "0x20000000000001",
    meaning: "linked-virtual-address",
    execution_status: "unknown",
  },
  runtime_load_base: null,
  sections: [
    {
      index: 0,
      name: {
        display: "opaque",
        bytes_base64: "b3BhcXVl",
        location: { offset: "0x40", bytes: "0x7" },
        unknown_reason: null,
      },
      name_offset: "0x0",
      type: "SHT_NOBITS",
      header_location: { offset: "0x0", bytes: "0x40" },
      address: "0x20000000000001",
      offset: "0xffffffffffffffff",
      size: "0x2000",
      alignment: "0x1",
      flags: "0x3",
      link: 0,
      info: 0,
      entry_size: "0x0",
      file_backing: "none",
    },
  ],
  segments: [],
  symbols: [],
  relocations: [],
  linkage: {
    needed_libraries: [],
    interpreters: [],
    got: [],
    plt: [],
    convenience_maps_completeness: "unknown",
    runtime_library_paths: null,
  },
  mitigations: {
    evidence_kind: "inferred",
    position_independent: false,
    nx_indicator: null,
    executable_stack_indicator: false,
    stack_canary_indicator: false,
    relro: null,
  },
  diagnostics: { stdout: "", stderr: "" },
  limitations: [],
});

it("retains high linked values and NOBITS without inventing file backing", () => {
  const value = binaryLayoutSchema.parse(report());
  expect(value.entry_point.reported_value).toBe("0x20000000000001");
  expect(value.sections[0]?.offset).toBe("0xffffffffffffffff");
  expect(value.runtime_load_base).toBeNull();
});

it.each([
  "file-backed-outside",
  "header-outside",
  "wrong-index",
  "noncanonical-base64",
  "wrong-machine",
  "outside-elf64",
])("rejects a malformed source representation: %s", (problem) => {
  const value = report();
  const section = value.sections[0];
  if (section === undefined) throw new Error("section missing");
  if (problem === "file-backed-outside") section.file_backing = "file";
  if (problem === "header-outside") section.header_location.offset = "0x80";
  if (problem === "wrong-index") section.index = 1;
  if (problem === "wrong-machine") value.architecture.machine = "EM_AARCH64";
  if (problem === "outside-elf64")
    value.entry_point.reported_value = "0x10000000000000000";
  if (problem === "noncanonical-base64") section.name.bytes_base64 = "AR==";
  expect(binaryLayoutSchema.safeParse(value).success).toBe(false);
});
