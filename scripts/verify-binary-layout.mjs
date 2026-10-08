#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const python = process.env.REA_PWNTOOLS_PYTHON;
const strace = process.env.REA_VERIFY_STRACE_COMMAND;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(python ?? "") ||
  !isAbsolute(strace ?? "")
)
  throw new Error(
    "verify:binary:layout requires Linux x64, absolute REA_PWNTOOLS_PYTHON (pwntools 4.15.0/pyelftools 0.33/Unicorn 2.1.2) and REA_VERIFY_STRACE_COMMAND. gcc, ld and strip must be available. No target is executed.",
  );
const run = createVerifierRun();
const execute = promisify(execFile);
for (const command of ["gcc", "ld", "strip", "/usr/bin/prlimit", strace]) {
  try {
    await execute(command, [command === strace ? "-V" : "--version"], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (cause) {
    throw new Error(
      `verify:binary:layout prerequisite unavailable: ${command}`,
      { cause },
    );
  }
}
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const root = await PrivateRuntimeRoot.create({
  prefix: "rea-layout-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({ name: "binary-layout-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const source = fileURLToPath(
  new URL("./fixtures/binary-layout.c", import.meta.url),
);
const highSource = fileURLToPath(
  new URL("./fixtures/binary-layout-high.S", import.meta.url),
);
let cases = 0;
const failures = [];
try {
  for (const [name, flags] of [
    [
      "protected",
      [
        "-fPIE",
        "-pie",
        "-fstack-protector-all",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,noexecstack",
      ],
    ],
    [
      "plain",
      [
        "-fno-pie",
        "-no-pie",
        "-fno-stack-protector",
        "-Wl,-z,norelro",
        "-Wl,-z,execstack",
      ],
    ],
    ["relocatable", ["-c", "-fcommon", "-fPIC"]],
    ["library", ["-shared", "-fPIC", "-fno-stack-protector"]],
  ])
    await execute(
      "gcc",
      ["-O1", "-g", ...flags, source, "-o", join(root.path, name)],
      { timeout: 30_000, maxBuffer: 1024 * 1024 },
    );
  const sectionlessBytes = await readFile(join(root.path, "protected"));
  sectionlessBytes.writeBigUInt64LE(0n, 40);
  sectionlessBytes.writeUInt16LE(0, 60);
  sectionlessBytes.writeUInt16LE(0, 62);
  await writeFile(join(root.path, "sectionless"), sectionlessBytes);
  const nullBytes = Buffer.from(await readFile(join(root.path, "protected")));
  const phOffset = Number(nullBytes.readBigUInt64LE(32));
  const phSize = nullBytes.readUInt16LE(54);
  const phCount = nullBytes.readUInt16LE(56);
  const unusedIndex = Array.from({ length: phCount }, (_, index) => index).find(
    (index) => nullBytes.readUInt32LE(phOffset + index * phSize) === 0x6474e551,
  );
  assert.notEqual(
    unusedIndex,
    undefined,
    "Required stack fixture header absent",
  );
  const unusedHeader = phOffset + unusedIndex * phSize;
  nullBytes.writeUInt32LE(0, unusedHeader);
  for (const field of [8, 32, 40])
    nullBytes.writeBigUInt64LE(0xffffffffffffffffn, unusedHeader + field);
  await writeFile(join(root.path, "unused-segment"), nullBytes);
  const emptyBytes = Buffer.from(nullBytes);
  emptyBytes.writeUInt32LE(1, unusedHeader);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 32);
  emptyBytes.writeBigUInt64LE(0n, unusedHeader + 40);
  await writeFile(join(root.path, "empty-segment"), emptyBytes);
  await copyFile(join(root.path, "protected"), join(root.path, "stripped"));
  await execute("strip", ["--strip-all", join(root.path, "stripped")], {
    timeout: 10_000,
  });
  await execute("gcc", ["-c", highSource, "-o", join(root.path, "high.o")], {
    timeout: 10_000,
  });
  await execute(
    "ld",
    [
      "-Ttext=0x20000000000001",
      "-o",
      join(root.path, "high"),
      join(root.path, "high.o"),
    ],
    { timeout: 10_000 },
  );
  await client.connect(transport);
  const reports = new Map();
  for (const name of [
    "protected",
    "plain",
    "relocatable",
    "library",
    "stripped",
    "sectionless",
    "unused-segment",
    "empty-segment",
    "high",
  ]) {
    const path = join(root.path, name);
    const bytes = await readFile(path);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, path);
      assert.equal(value.artifact.sha256, sha256);
      assert.equal(value.artifact.bytes, bytes.length);
      assert.equal(value.runtime_load_base, null);
      assert.equal(value.linkage.runtime_library_paths, null);
      assert.equal(value.mitigations.evidence_kind, "inferred");
      if (name === "sectionless") {
        assert.equal(value.sections.length, 0);
        assert.equal(value.symbols.length, 0);
        assert.deepEqual(
          value.linkage.needed_libraries,
          reports.get("protected").linkage.needed_libraries,
        );
        assert.ok(
          value.linkage.needed_libraries.every(
            (name) => name.location !== null && name.bytes_base64 !== null,
          ),
        );
        // Preserve the unchanged engine's section-dependent heuristic and its
        // explicit coverage limitation, rather than inventing a stronger label.
        assert.equal(value.mitigations.relro, "Partial");
        assert.ok(
          value.limitations.some((item) =>
            item.includes("RELRO/canary indicators may be incomplete"),
          ),
        );
      } else
        assert.ok(
          value.sections.some((section) => section.file_backing === "none"),
        );
      for (const section of value.sections) {
        assert.ok(typeof section.address === "string");
        if (section.file_backing === "file")
          assert.ok(
            BigInt(section.offset) + BigInt(section.size) <=
              BigInt(bytes.length),
          );
      }
      if (name === "unused-segment" || name === "empty-segment") {
        const segment = value.segments[unusedIndex];
        assert.equal(segment.file_backing, "none");
        assert.equal(segment.offset, "0xffffffffffffffff");
        if (name === "unused-segment") assert.equal(segment.permissions, null);
        else assert.notEqual(segment.permissions, null);
      }
      reports.set(name, value);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  const protectedReport = reports.get("protected");
  const fileSymbols = protectedReport.symbols.filter(
    (symbol) => symbol.type === "STT_FILE",
  );
  assert.ok(fileSymbols.length > 0);
  assert.ok(
    fileSymbols.every((symbol) => symbol.value_meaning === "no-address"),
  );
  const plain = reports.get("plain");
  assert.equal(protectedReport.mitigations.position_independent, true);
  assert.equal(protectedReport.mitigations.nx_indicator, true);
  assert.equal(protectedReport.mitigations.stack_canary_indicator, true);
  assert.equal(protectedReport.mitigations.relro, "Full");
  assert.equal(plain.mitigations.position_independent, false);
  assert.equal(plain.mitigations.nx_indicator, null);
  assert.equal(plain.mitigations.executable_stack_indicator, true);
  assert.equal(protectedReport.mitigations.executable_stack_indicator, false);
  assert.equal(plain.mitigations.stack_canary_indicator, false);
  assert.equal(plain.mitigations.relro, null);
  const relocatable = reports.get("relocatable");
  assert.equal(relocatable.entry_point.meaning, "not-applicable");
  assert.ok(relocatable.relocations.length > 0);
  assert.ok(
    relocatable.relocations.every(
      (item) => item.target.kind === "section-offset",
    ),
  );
  assert.ok(
    relocatable.relocations.some((item) => BigInt(item.addend ?? "0") < 0n),
  );
  assert.equal(
    relocatable.symbols.find((symbol) => symbol.name.display === "common_value")
      .value_meaning,
    "alignment",
  );
  assert.equal(
    reports
      .get("library")
      .symbols.find((symbol) => symbol.name.display === "tls_value")
      .value_meaning,
    "tls-offset",
  );
  assert.equal(
    reports.get("high").entry_point.reported_value,
    "0x20000000000001",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value").value,
    "0x20000000000007",
  );
  assert.equal(
    reports
      .get("high")
      .symbols.find((symbol) => symbol.name.display === "absolute_value")
      .value_meaning,
    "absolute-value",
  );
  assert.ok(
    reports.get("stripped").symbols.length < protectedReport.symbols.length,
  );
  const object = await readFile(join(root.path, "relocatable"));
  const name = relocatable.symbols.find(
    (symbol) => symbol.name.display === "read_values",
  ).name;
  const changed = Buffer.from(object);
  changed[Number(BigInt(name.location.offset))] = 0xff;
  const opaque = join(root.path, "opaque-name.o");
  await writeFile(opaque, changed);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, opaque);
    const symbol = value.symbols.find((item) =>
      item.name.display.endsWith("ead_values"),
    );
    assert.equal(Buffer.from(symbol.name.bytes_base64, "base64")[0], 0xff);
    assert.equal(symbol.name.location.offset, name.location.offset);
    assert.deepEqual(await readFile(opaque), changed);
    cases++;
  }
  const sectionBearingBytes = await readFile(join(root.path, "protected"));
  const zeroSymbolEntries = ["SHT_SYMTAB", "SHT_DYNSYM"].map((type) => {
    const section = protectedReport.sections.find((item) => item.type === type);
    assert.notEqual(
      section,
      undefined,
      `Required fixture table absent: ${type}`,
    );
    const bytes = Buffer.from(sectionBearingBytes);
    bytes.writeBigUInt64LE(
      0n,
      Number(BigInt(section.header_location.offset)) + 56,
    );
    return [`zero-entry-${type}`, bytes, "invalid_input"];
  });
  const symbolTable = relocatable.sections.find(
    (section) => section.type === "SHT_SYMTAB",
  );
  assert.notEqual(symbolTable, undefined);
  const symbol = relocatable.symbols.find(
    (item) => item.name.display === "read_values",
  );
  assert.notEqual(symbol, undefined);
  const extendedWords = Buffer.alloc(
    Number(BigInt(symbolTable.size) / BigInt(symbolTable.entry_size)) * 4,
  );
  extendedWords.writeUInt32LE(symbol.section_index, symbol.entry_index * 4);
  const headers = Buffer.from(
    object.subarray(
      Number(BigInt(relocatable.sections[0].header_location.offset)),
      Number(
        BigInt(relocatable.sections.at(-1).header_location.offset) +
          BigInt(relocatable.sections.at(-1).header_location.bytes),
      ),
    ),
  );
  const extendedHeader = Buffer.alloc(64);
  extendedHeader.writeUInt32LE(18, 4); // SHT_SYMTAB_SHNDX
  extendedHeader.writeBigUInt64LE(BigInt(object.length), 24);
  extendedHeader.writeBigUInt64LE(BigInt(extendedWords.length), 32);
  extendedHeader.writeUInt32LE(symbolTable.index, 40);
  extendedHeader.writeBigUInt64LE(4n, 48);
  extendedHeader.writeBigUInt64LE(4n, 56);
  const extendedObject = Buffer.concat([
    object,
    extendedWords,
    headers,
    extendedHeader,
  ]);
  extendedObject.writeBigUInt64LE(
    BigInt(object.length + extendedWords.length),
    40,
  );
  extendedObject.writeUInt16LE(relocatable.sections.length + 1, 60);
  extendedObject.writeUInt16LE(
    0xffff,
    Number(BigInt(symbol.location.offset)) + 6,
  );
  const extendedPath = join(root.path, "external-symbol-index.o");
  await writeFile(extendedPath, extendedObject);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, extendedPath);
    const reported = value.symbols.find(
      (item) => item.name.display === "read_values",
    );
    assert.equal(reported.section_index, 0xffff);
    assert.equal(reported.value_meaning, "unknown-section-index");
    assert.ok(
      value.sections.some((section) => section.type === "SHT_SYMTAB_SHNDX"),
    );
    assert.deepEqual(await readFile(extendedPath), extendedObject);
    cases++;
  }
  for (const [name, option, expected] of [
    ["address-space", "--as=2147483648", '"address_space_bytes": 2147483648'],
    ["cpu", "--cpu=20", '"cpu_seconds": 20'],
    ["file-size", "--fsize=33554432", '"file_size_bytes": 33554432'],
  ]) {
    const wrapper = join(root.path, `python-limit-${name}`);
    const quotedPython = "'" + python.replaceAll("'", "'\"'\"'") + "'";
    await writeFile(
      wrapper,
      `#!/bin/sh\nexec /usr/bin/prlimit ${option} -- ${quotedPython} "$@"\n`,
      { mode: 0o700 },
    );
    const limitedEnvironment = { ...environment, REA_PWNTOOLS_PYTHON: wrapper };
    const limitedClient = new Client({
      name: "limited-layout-verifier",
      version: "1",
    });
    const limitedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: limitedEnvironment,
      stderr: "pipe",
    });
    try {
      await limitedClient.connect(limitedTransport);
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(
          mode,
          join(root.path, "protected"),
          undefined,
          limitedEnvironment,
          limitedClient,
        );
        assert.ok(value.limitations.some((item) => item.includes(expected)));
        cases++;
      }
    } finally {
      try {
        await limitedClient.close();
      } finally {
        await limitedTransport.close();
      }
    }
  }
  const unsupported = Buffer.from(object);
  unsupported.writeUInt16LE(183, 18);
  const core = Buffer.from(object);
  core.writeUInt16LE(4, 16);
  for (const [name, bytes, category] of [
    ["not-elf", Buffer.from("ordinary local text"), "invalid_input"],
    ["truncated", object.subarray(0, 32), "invalid_input"],
    [
      "truncated-tables",
      object.subarray(0, object.length - 1),
      "invalid_input",
    ],
    ...zeroSymbolEntries,
    ["arm64", unsupported, "unsupported_provider"],
    ["core", core, "unsupported_provider"],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, bytes);
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, path, category);
      assert.deepEqual(await readFile(path), bytes);
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, join(root.path, "absent"), "invalid_input");
    cases++;
  }
  for (const name of ["protected", "sectionless"]) {
    const trace = join(root.path, `exec.trace.${name}`);
    await execute(
      strace,
      [
        "-ff",
        "-e",
        "trace=execve,execveat",
        "-s",
        "4096",
        "-o",
        trace,
        process.execPath,
        entrypoint,
        "inspect-binary-layout",
        join(root.path, name),
        "--json",
      ],
      {
        env: { ...environment, PATH: "/usr/bin:/bin" },
        timeout: 45_000,
        maxBuffer: 64 * 1024 * 1024,
      },
    );
  }
  const executions = [];
  for (const file of await readdir(root.path)) {
    if (!file.startsWith("exec.trace.")) continue;
    for (const line of (await readFile(join(root.path, file), "utf8")).split(
      "\n",
    )) {
      if (!/execve(?:at)?\(/.test(line)) continue;
      const match = /^execve\("([^\"]+)"/.exec(line);
      assert.notEqual(
        match,
        null,
        `Unresolved executable identity in syscall trace: ${line}`,
      );
      assert.ok(
        line.endsWith(" = 0") || / = -1 [A-Z]+/.test(line),
        `Incomplete exec observation: ${line}`,
      );
      const ownershipInspection =
        ["/usr/bin/ps", "/bin/ps"].includes(match[1]) &&
        line.includes('["ps", "-axo", "pid=,ppid=,pgid=,stat=,command="]');
      assert.ok(
        [process.execPath, python].includes(match[1]) || ownershipInspection,
        `Unexpected attempted host execution: ${line}`,
      );
      executions.push(match[1]);
    }
  }
  assert.ok(executions.includes(process.execPath));
  assert.ok(executions.includes(python));
  cases += 2;
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    () => client.close(),
    () => transport.close(),
    () => root.close(),
  ]) {
    try {
      await close();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Offline binary layout verification failed; cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      profile: "pwntools4.15.0/pyelftools0.33/Unicorn2.1.2",
      target_execution: "exec-syscalls-verified-absent",
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(
  mode,
  path,
  category,
  selectedEnvironment = environment,
  selectedClient = client,
) {
  let envelope;
  if (mode === "mcp") {
    const response = await selectedClient.callTool({
      name: "inspect_binary_layout",
      arguments: { path },
    });
    const value = JSON.parse(mcpTextValue(response));
    if (category !== undefined) {
      assert.equal(response.isError, true);
      assert.equal(value.error.category, category);
      return value.error;
    }
    assert.notEqual(response.isError, true, mcpTextValue(response));
    envelope = value.evidence;
    assert.deepEqual(value.result, envelope.normalized_result);
  } else {
    try {
      const response = await execute(
        process.execPath,
        [entrypoint, "inspect-binary-layout", path, "--json"],
        {
          env: selectedEnvironment,
          timeout: 40_000,
          maxBuffer: 64 * 1024 * 1024,
        },
      );
      assert.equal(category, undefined, "Expected selected input to fail");
      envelope = JSON.parse(response.stdout);
    } catch (cause) {
      if (category === undefined) throw cause;
      assert.equal(typeof cause.code, "number");
      const error = JSON.parse(cause.stdout);
      assert.equal(error.category, category);
      return error;
    }
  }
  const evidence = parseEvidence(envelope);
  assert.equal(evidence.subject.local_path, path);
  assert.equal(
    evidence.provider.version,
    "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2",
  );
  assert.deepEqual(evidence.normalized_result, evidence.raw_result);
  return evidence.normalized_result;
}
