import {
  inspectBinaryLayoutInputSchema,
  binaryLayoutSchema,
} from "../../domain/native/binaryLayout.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemas.js";

/** Offline binary diagnostics are independent of macOS process/UI providers. */
export const BINARY_DIAGNOSTICS_TOOL_CONTRACTS = [
  {
    name: "inspect_binary_layout",
    ...toolContractMetadata("inspect_binary_layout"),
    kind: "native-provider",
    description:
      "Inspect an explicit local binary without launching it as a host process. Returns file-backed section/segment ranges, linked addresses, original symbol/REL/RELA table identities, complete encoded RELR tables and upstream-derived offsets with unknown per-word locations/addends, raw name bytes, dependency/interpreter names and static mitigation inferences inline with artifact SHA-256 Evidence. Initial profile: ELF64 x86-64 little-endian EXEC/DYN/REL on Linux x64 via caller-supplied Python with unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2. Runtime addresses/library paths, overall relocation inventory completeness and complete derived GOT/PLT coverage remain unknown. Zero executable entry values mean absence; relocatable entries are not applicable. Upstream can emulate PLT instructions with Unicorn for derived static maps. Uses bounded complete output and owned temporary files/processes; malformed, unsupported or oversized objects return no partial success.",
    inputSchema: inspectBinaryLayoutInputSchema,
    outputSchema: evidenceResultOf(binaryLayoutSchema),
    examples: [
      {
        title: "Inspect ELF linked and file layout",
        input: { path: "/artifacts/application.elf" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
