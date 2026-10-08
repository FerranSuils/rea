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
  packed_relative_relocations: [],
  relocation_inventory_completeness: "unknown",
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
  diagnostics: { stdout: "", stderr: "", truncated: false },
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

it.each([
  ["PT_NULL", "0xffffffffffffffff", "none", null, true],
  ["PT_LOAD", "0x0", "none", { read: true, write: true, execute: false }, true],
  [
    "PT_LOAD",
    "0x1",
    "file",
    { read: true, write: false, execute: false },
    false,
  ],
  ["PT_NULL", "0x1", "file", null, false],
  [
    "PT_NULL",
    "0x1",
    "none",
    { read: false, write: false, execute: false },
    false,
  ],
  [
    "PT_LOAD",
    "0x1",
    "none",
    { read: true, write: false, execute: false },
    false,
  ],
])(
  "validates actual segment backing/meaning for %s size %s",
  (type, fileSize, backing, permissions, valid) => {
    const value = {
      ...report(),
      segments: [
        {
          index: 0,
          type,
          header_location: { offset: "0x0", bytes: "0x38" },
          offset: "0xffffffffffffffff",
          file_size: fileSize,
          memory_size: fileSize,
          virtual_address: "0x0",
          physical_address: "0x0",
          alignment: "0x0",
          flags: "0x0",
          file_backing: backing,
          permissions,
        },
      ],
    };
    expect(binaryLayoutSchema.safeParse(value).success).toBe(valid);
  },
);

it.each([
  ["ET_EXEC", "0x0", "absent", true],
  ["ET_DYN", "0x0", "linked-virtual-address", false],
  ["ET_REL", "0x0", "not-applicable", true],
  ["ET_EXEC", "0x1", "absent", false],
])(
  "validates actual entry meaning: %s %s %s",
  (imageType, entry, meaning, valid) => {
    expect(
      binaryLayoutSchema.safeParse({
        ...report(),
        image_type: imageType,
        entry_point: {
          reported_value: entry,
          meaning,
          execution_status: "unknown",
        },
      }).success,
    ).toBe(valid);
  },
);

it.each([
  "valid",
  "byte-length",
  "section-identity",
  "decoded-order",
  "noncanonical-bytes",
])(
  "retains original packed bytes and derived offset provenance: %s",
  (problem) => {
    const value = report();
    const section = value.sections[0];
    if (section === undefined) throw new Error("section missing");
    section.type = "SHT_RELR";
    section.file_backing = "file";
    section.offset = "0x60";
    section.size = "0x8";
    const table = {
      section_index: 0,
      location: { offset: "0x60", bytes: "0x8" },
      encoded_bytes_base64: "AAAAAAAAAAA=",
      entries: [{ decoded_index: 0, reported_offset: "0x20000000000001" }],
      offset_meaning: "linked-virtual-address",
      evidence_kind: "derived",
      entry_source_locations: null,
      addends: null,
    };
    if (problem === "byte-length") table.location.bytes = "0x7";
    if (problem === "section-identity") table.section_index = 1;
    if (problem === "decoded-order")
      table.entries[0] = { decoded_index: 1, reported_offset: "0x0" };
    if (problem === "noncanonical-bytes") table.encoded_bytes_base64 = "AB==";
    expect(
      binaryLayoutSchema.safeParse({
        ...value,
        packed_relative_relocations: [table],
      }).success,
    ).toBe(problem === "valid");
  },
);
