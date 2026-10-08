import { z } from "zod";

const unsignedHex = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/);
const index = z.number().int().nonnegative();
const scalar = z.union([z.string(), z.number().int()]);
const range = z.strictObject({ offset: unsignedHex, bytes: unsignedHex });
const name = z.strictObject({
  display: z.string(),
  bytes_base64: z
    .string()
    .regex(
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/,
    )
    .nullable(),
  location: range.nullable(),
  unknown_reason: z.string().nullable(),
});

/** Explicit local object selection, independent of an active disassembler target. */
export const inspectBinaryLayoutInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe("Absolute filesystem path to the selected binary"),
});

/** File and linked-image evidence; numeric ELF values never pass through unsafe JSON numbers. */
const binaryLayoutObjectSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: index,
  }),
  format: z.literal("elf"),
  architecture: z.strictObject({
    machine: z.literal("EM_X86_64"),
    bits: z.literal(64),
    byte_order: z.literal("little"),
  }),
  image_type: z.enum(["ET_EXEC", "ET_DYN", "ET_REL"]),
  entry_point: z.strictObject({
    reported_value: unsignedHex,
    meaning: z.enum(["linked-virtual-address", "not-applicable"]),
    execution_status: z.literal("unknown"),
  }),
  runtime_load_base: z.null(),
  sections: z.array(
    z.strictObject({
      index,
      name,
      name_offset: unsignedHex,
      type: scalar,
      header_location: range,
      address: unsignedHex,
      offset: unsignedHex,
      size: unsignedHex,
      alignment: unsignedHex,
      flags: unsignedHex,
      link: index,
      info: index,
      entry_size: unsignedHex,
      file_backing: z.enum(["file", "none"]),
    }),
  ),
  segments: z.array(
    z.strictObject({
      index,
      type: scalar,
      header_location: range,
      offset: unsignedHex,
      file_size: unsignedHex,
      memory_size: unsignedHex,
      virtual_address: unsignedHex,
      physical_address: unsignedHex,
      alignment: unsignedHex,
      flags: unsignedHex,
      file_backing: z.enum(["file", "none"]),
      permissions: z
        .strictObject({
          read: z.boolean(),
          write: z.boolean(),
          execute: z.boolean(),
        })
        .nullable(),
    }),
  ),
  symbols: z.array(
    z.strictObject({
      table_index: index,
      entry_index: index,
      name,
      name_offset: unsignedHex,
      location: range,
      value: unsignedHex,
      value_meaning: z.enum([
        "undefined",
        "alignment",
        "absolute-value",
        "no-address",
        "unknown-section-index",
        "section-offset",
        "tls-offset",
        "linked-virtual-address",
      ]),
      size: unsignedHex,
      binding: scalar,
      type: scalar,
      visibility: scalar,
      section_index: scalar,
    }),
  ),
  relocations: z.array(
    z.strictObject({
      section_index: index,
      entry_index: index,
      reported_offset: unsignedHex,
      target: z.discriminatedUnion("kind", [
        z.strictObject({
          kind: z.literal("section-offset"),
          section_index: index,
          offset: unsignedHex,
        }),
        z.strictObject({
          kind: z.literal("linked-virtual-address"),
          address: unsignedHex,
        }),
      ]),
      location: range,
      type: index,
      symbol_table_index: index,
      symbol_index: index,
      addend: z
        .string()
        .regex(/^-?(?:0|[1-9][0-9]{0,18})$/)
        .nullable(),
    }),
  ),
  linkage: z.strictObject({
    needed_libraries: z.array(name),
    interpreters: z.array(name),
    got: z.array(
      z.strictObject({ display_name: z.string(), address: unsignedHex }),
    ),
    plt: z.array(
      z.strictObject({ display_name: z.string(), address: unsignedHex }),
    ),
    convenience_maps_completeness: z.literal("unknown"),
    runtime_library_paths: z.null(),
  }),
  mitigations: z.strictObject({
    evidence_kind: z.literal("inferred"),
    position_independent: z.boolean(),
    nx_indicator: z.boolean().nullable(),
    executable_stack_indicator: z.boolean(),
    stack_canary_indicator: z.boolean(),
    relro: z.enum(["Partial", "Full"]).nullable(),
  }),
  diagnostics: z.strictObject({ stdout: z.string(), stderr: z.string() }),
  limitations: z.array(z.string()),
});

/** Decoder payload excludes the artifact identity observed by the owning process boundary. */
export const binaryLayoutPayloadSchema = binaryLayoutObjectSchema.omit({
  artifact: true,
  diagnostics: true,
});

/** Check source ranges again at the public boundary, independently of upstream parsing. */
export const binaryLayoutSchema = binaryLayoutObjectSchema.superRefine(
  (value, context) => {
    const size = BigInt(value.artifact.bytes);
    const check = (
      offset: string,
      length: string,
      path: (string | number)[],
    ): void => {
      const start = BigInt(offset);
      const bytes = BigInt(length);
      if (start > size || bytes > size - start)
        context.addIssue({
          code: "custom",
          path,
          message:
            "Reported file-backed range lies outside the selected artifact.",
        });
    };
    const checkLocation = (
      where: z.infer<typeof range>,
      path: (string | number)[],
    ): void => check(where.offset, where.bytes, path);
    const checkName = (
      reported: z.infer<typeof name>,
      path: (string | number)[],
    ): void => {
      if (reported.location !== null)
        checkLocation(reported.location, [...path, "location"]);
    };
    for (const [index, section] of value.sections.entries()) {
      if (section.index !== index)
        context.addIssue({
          code: "custom",
          path: ["sections", index, "index"],
          message:
            "Complete section order must preserve original producer indices.",
        });
      checkLocation(section.header_location, [
        "sections",
        index,
        "header_location",
      ]);
      checkName(section.name, ["sections", index, "name"]);
      if (section.file_backing === "file")
        check(section.offset, section.size, ["sections", index]);
    }
    for (const [index, segment] of value.segments.entries()) {
      if (segment.index !== index)
        context.addIssue({
          code: "custom",
          path: ["segments", index, "index"],
          message:
            "Complete segment order must preserve original producer indices.",
        });
      checkLocation(segment.header_location, [
        "segments",
        index,
        "header_location",
      ]);
      const hasFileBytes =
        segment.type !== "PT_NULL" && BigInt(segment.file_size) !== 0n;
      if (segment.file_backing !== (hasFileBytes ? "file" : "none"))
        context.addIssue({
          code: "custom",
          path: ["segments", index, "file_backing"],
          message:
            "File backing must follow the reported segment type and file size.",
        });
      if ((segment.type === "PT_NULL") !== (segment.permissions === null))
        context.addIssue({
          code: "custom",
          path: ["segments", index, "permissions"],
          message:
            "Unused PT_NULL flags have no permission meaning; other segment flags retain their interpretation.",
        });
      if (hasFileBytes)
        check(segment.offset, segment.file_size, ["segments", index]);
    }
    for (const [index, symbol] of value.symbols.entries()) {
      checkLocation(symbol.location, ["symbols", index, "location"]);
      checkName(symbol.name, ["symbols", index, "name"]);
    }
    for (const [index, relocation] of value.relocations.entries())
      checkLocation(relocation.location, ["relocations", index, "location"]);
    for (const facet of ["needed_libraries", "interpreters"] as const)
      for (const [index, reported] of value.linkage[facet].entries())
        checkName(reported, ["linkage", facet, index]);
  },
);

export type InspectBinaryLayoutInput = z.infer<
  typeof inspectBinaryLayoutInputSchema
>;
export type BinaryLayout = z.infer<typeof binaryLayoutSchema>;
