# Offline binary diagnostics

`inspect_binary_layout` / `inspect-binary-layout` answers what an explicit
file contains: section/segment layout, original symbols/relocations, static
linkage names and mitigation indicators. It works without an active Hopper,
Ghidra or IDA target. CTF is one possible use; crash triage, compatibility and
ordinary binary inspection use the same modular capability.

## Bring your own engine

Initial real verification covers **Linux x64, ELF64 x86-64 little-endian
EXEC/DYN/REL**. Provide an absolute Python executable whose environment already
contains unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2:

```sh
REA_PWNTOOLS_PYTHON=/absolute/isolated-env/bin/python \
  rea inspect-binary-layout ./selected.elf --json
```

```json
{
  "name": "inspect_binary_layout",
  "arguments": { "path": "/artifacts/selected.elf" }
}
```

REA never installs Python, packages or GDB, changes a user init file, executes
the selected object, or requests runtime library resolution. The Python process
uses isolated mode and an owned cache. Exact upstream profiles are recorded in
[upstream provenance](../third_party/pwntools/README.md).

## Interpreting results

- Artifact path, SHA-256 and size identify original selected bytes. All parsing
  reads an owned stable snapshot; the original is unchanged.
- Addresses, offsets, lengths and flags are hexadecimal strings. A linked
  address is not a runtime address. Runtime load base remains null.
- Each symbol retains its table and entry index. Its reported value can mean
  undefined, alignment, absolute value, no address, unknown section index,
  section offset, TLS offset or linked virtual address. Duplicate names remain
  separate entries.
- Relocatable objects have section-relative relocations and no executable entry
  claim. Signed relocation addends are decimal strings.
- Name display strings may contain upstream replacement characters. Raw name
  bytes and string-table ranges retain observed identity where resolvable;
  ranges include the terminating NUL and base64 bytes exclude it.
- NOBITS and NULL sections provide no file bytes. Reported file-backed ranges
  are checked against snapshot size again at the public boundary.
- DT_NEEDED/PT_INTERP are reported names, not resolved runtime paths. GOT/PLT
  maps are derived convenience views and may collapse aliases; completeness
  remains unknown and original upstream warnings are returned inline.
- Canary, PIE, NX, executable-stack and RELRO are static inferences. NX and
  executable-stack are separate upstream indicators: on x86-64 an executable
  stack can accompany an unknown (`null`) NX indicator. ET_DYN can be a shared
  library, and an absent canary symbol does not prove every function unprotected.

Complete results have a 32 MiB input, 64 MiB reply, 1 MiB combined diagnostics
and 30-second owned command deadline. Python has 3 GiB virtual address space,
30 CPU seconds and 64 MiB file output limits. Virtual address space is not RSS;
Unicorn needs a large virtual map. Limits fail with no partial success, and
owned process/root cleanup completes independently of cancellation.

Core files, GDB session/state/control, optional pwndbg enrichment and instruction
inspection are separate increments tracked by #969. This increment makes no
real support claim for those features or other operating systems/architectures.
