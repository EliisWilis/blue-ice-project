#!/usr/bin/env node
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const command = args[0] ?? "help";

function printHelp(): void {
  process.stdout.write(
    "Blue Ice Project terminal client\n\n" +
      "Commands:\n" +
      "  blue-ice-node init [options]          Create local policy and auth token\n" +
      "  blue-ice-node start [options]         Start the local proxy\n" +
      "  blue-ice-node audit [options]         Show metadata-only audit events\n" +
      "  blue-ice-node provider add ...        Register a trusted HTTPS endpoint\n" +
      "  blue-ice-node provider use ...        Select one provider explicitly\n" +
      "  blue-ice-node provider list           List configured providers\n" +
      "  blue-ice-node models [--port N]       Query the local OpenAI-compatible API\n" +
      "  blue-ice-node help                    Show this help\n\n" +
      "Provider keys are loaded by the Python service from the OS keyring or a provider-specific environment variable.\n",
  );
}

async function runPythonCli(subargs: string[]): Promise<number> {
  const child = spawn("blue-ice", subargs, { stdio: "inherit", windowsHide: true });
  return await new Promise<number>((resolve, reject) => {
    child.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") {
        reject(new Error("Python CLI was not found. Install Blue Ice Project with `pip install .` first."));
        return;
      }
      reject(new Error("Could not start the Blue Ice Project Python service."));
    });
    child.once("exit", (code, signal) => {
      resolve(code ?? (signal ? 1 : 0));
    });
  });
}

async function readLocalToken(): Promise<string> {
  const path = process.env.BLUE_ICE_TOKEN_FILE ?? join(homedir(), ".aegis", "local-token");
  let file: Awaited<ReturnType<typeof open>> | undefined;
  try {
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const info = await file.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0 || info.uid !== process.getuid?.() || info.size > 512) {
      throw new Error("Local token file must be a private regular file owned by the current user.");
    }
    const token = (await file.readFile({ encoding: "utf8" })).trim();
    if (token.length < 32 || token.length > 512) {
      throw new Error("Local token file has an invalid format.");
    }
    return token;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Local token")) throw error;
    throw new Error("Local token file could not be read. Run `blue-ice init` first.");
  } finally {
    await file?.close();
  }
}

async function showModels(): Promise<void> {
  const portText = args[1] === "--port" ? args[2] : undefined;
  const port = portText === undefined ? 8080 : Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Port must be an integer between 1 and 65535.");
  }
  const token = await readLocalToken();
  let response: Response;
  try {
    response = await fetch(`http://127.0.0.1:${port}/v1/models`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(5000),
      redirect: "error",
    });
  } catch {
    throw new Error("Could not connect to the local proxy. Start it with `blue-ice start`.");
  }
  if (!response.ok) {
    throw new Error(`Local proxy returned HTTP ${response.status}. Check its status and local token.`);
  }
  const body: unknown = await response.json();
  if (typeof body !== "object" || body === null || !("data" in body) || !Array.isArray(body.data)) {
    throw new Error("Local proxy returned an invalid models response.");
  }
  process.stdout.write("Configured models:\n");
  for (const model of body.data) {
    if (typeof model === "object" && model !== null && "id" in model && typeof model.id === "string") {
      process.stdout.write(`  ${model.id}\n`);
    }
  }
}

try {
  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
  } else if (command === "models") {
    await showModels();
  } else if (["init", "start", "audit", "provider"].includes(command)) {
    const code = await runPythonCli(args);
    process.exitCode = code;
  } else {
    printHelp();
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "Blue Ice Project command failed."}\n`);
  process.exitCode = 1;
}
