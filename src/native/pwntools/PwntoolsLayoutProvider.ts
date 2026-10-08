import {
  pwntoolsLayoutFailure,
  pwntoolsUnavailable,
} from "./PwntoolsFailures.js";
import { randomUUID } from "node:crypto";
import { access, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type { BinaryLayoutPort } from "../../application/binaryDiagnostics/BinaryLayoutPort.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  binaryLayoutPayloadSchema,
  type BinaryLayout,
  type InspectBinaryLayoutInput,
} from "../../domain/native/binaryLayout.js";
import { runOwnedCommand } from "../../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import {
  PWNTOOLS_PROVIDER_IDENTITY,
  PWNTOOLS_LIMITS,
} from "./PwntoolsRelease.js";

const OPERATION = "inspect_binary_layout";
const decoded = binaryLayoutPayloadSchema;
const replySchema = z.discriminatedUnion("ok", [
  z.strictObject({
    ok: z.literal(true),
    profile: z.literal(PWNTOOLS_PROVIDER_IDENTITY.version),
    value: decoded,
  }),
  z.strictObject({
    ok: z.literal(false),
    reason: z.enum([
      "format",
      "unsupported",
      "unavailable",
      "resource-limit",
      "output-limit",
      "decoder",
    ]),
    message: z.string(),
  }),
]);

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];

/** Thin owned-process adapter; all ELF parsing and heuristics come from unchanged upstream code. */
export class PwntoolsLayoutProvider implements BinaryLayoutPort {
  readonly identity = PWNTOOLS_PROVIDER_IDENTITY;
  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv>,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<
      Pick<PrivateRuntimeRoot, "path" | "close">
    > = () => PrivateRuntimeRoot.create({ prefix: "rea-elf-layout-" }),
  ) {}

  /** Snapshot one explicit artifact and return complete static observations without executing its bytes. */
  async inspect(
    input: InspectBinaryLayoutInput,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryLayout, AnalysisError>> {
    let root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
    let result: Result<BinaryLayout, AnalysisError>;
    let phase: "configuration" | "artifact-read" | "decoder" = "configuration";
    let selectedPath = this.environment.REA_PWNTOOLS_PYTHON ?? "";
    try {
      if (options?.signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      if (process.platform !== "linux" || process.arch !== "x64")
        throw new AnalysisCapabilityUnavailableError(
          this.identity.id,
          OPERATION,
          "The real-verified pwntools layout profile currently supports Linux x64 only.",
        );
      if (!isAbsolute(selectedPath))
        throw pwntoolsUnavailable(
          "Set REA_PWNTOOLS_PYTHON to an absolute caller-supplied Python executable with pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2; REA never installs Python or packages.",
          selectedPath,
        );
      await access(selectedPath, constants.X_OK);
      phase = "artifact-read";
      selectedPath = input.path;
      const snapshot = await readStableArtifact(
        input.path,
        PWNTOOLS_LIMITS.inputBytes,
        options?.signal,
      );
      phase = "decoder";
      root = await this.createRuntime();
      const requestPath = join(root.path, "request.json");
      const snapshotPath = join(root.path, "object.snapshot");
      const replyPath = join(root.path, "reply.json");
      await writeFile(snapshotPath, snapshot.bytes, {
        flag: "wx",
        mode: 0o600,
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
      });
      await writeFile(
        requestPath,
        JSON.stringify({ snapshot_path: snapshotPath, reply_path: replyPath }),
        { flag: "wx", mode: 0o600 },
      );
      const execution = await runOwnedCommand(
        {
          command: this.environment.REA_PWNTOOLS_PYTHON ?? "",
          arguments: [
            "-I",
            fileURLToPath(
              new URL("../../../bridge/pwntools/layout.py", import.meta.url),
            ),
            requestPath,
          ],
          cwd: root.path,
          runId: `rea-elf-layout-${randomUUID()}`,
          hostEnvironment: {
            ...this.environment,
            PWNLIB_NOTERM: "1",
            OPENBLAS_NUM_THREADS: "1",
            OMP_NUM_THREADS: "1",
          },
        },
        {
          timeoutMs: PWNTOOLS_LIMITS.timeoutMs,
          diagnosticBytes: PWNTOOLS_LIMITS.diagnosticBytes,
        },
        {
          ...(options?.signal === undefined ? {} : { signal: options.signal }),
          ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
        },
      );
      let reply: z.output<typeof replySchema>;
      try {
        const file = await readStableArtifact(
          replyPath,
          PWNTOOLS_LIMITS.outputBytes,
          options?.signal,
        );
        reply = replySchema.parse(JSON.parse(file.bytes.toString("utf8")));
      } catch (cause: unknown) {
        if (options?.signal?.aborted)
          throw new AnalysisCancelledError(OPERATION);
        throw new AnalysisOutputError(
          OPERATION,
          `Owned ELF decoder reply failed for ${input.path}: ${cause instanceof z.ZodError ? cause.issues[0]?.message + " at " + (cause.issues[0]?.path.map(String).join(".") ?? "root") : cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        );
      }
      if (!reply.ok) {
        if (reply.reason === "format")
          throw new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["path"],
              reason: "invalid_format",
              message: reply.message,
            },
          ]);
        if (reply.reason === "unavailable")
          throw pwntoolsUnavailable(
            reply.message,
            this.environment.REA_PWNTOOLS_PYTHON ?? "",
          );
        if (reply.reason === "unsupported")
          throw new AnalysisCapabilityUnavailableError(
            this.identity.id,
            OPERATION,
            reply.message,
            { userMessage: reply.message },
          );
        if (reply.reason === "output-limit")
          throw new AnalysisOutputError(OPERATION, reply.message);
        throw new ProviderAdapterError(this.identity.id, OPERATION, {
          diagnostics: {
            phase,
            failure_kind: reply.reason,
            reason: reply.message,
            stdout: execution.stdout.text,
            stderr: execution.stderr.text,
          },
        });
      }
      result = ok({
        ...reply.value,
        artifact: {
          path: input.path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        },
        diagnostics: {
          stdout: execution.stdout.text,
          stderr: execution.stderr.text,
        },
      });
    } catch (cause: unknown) {
      result = err(pwntoolsLayoutFailure(cause, phase, selectedPath));
    }
    if (root !== undefined) {
      try {
        await root.close();
      } catch (cause: unknown) {
        return err(
          new ProviderCleanupError(
            this.identity.id,
            [root.path],
            {
              reason: cause instanceof Error ? cause.message : String(cause),
              previous_error: result.ok
                ? null
                : projectAnalysisError(result.error),
            },
            { operation: OPERATION },
          ),
        );
      }
    }
    return result.ok && options?.signal?.aborted
      ? err(new AnalysisCancelledError(OPERATION))
      : result;
  }
}
