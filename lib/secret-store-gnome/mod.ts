// Secret store — gnome-keyring / libsecret via secret-tool CLI.
// Implements KeychainStore from app-attest-abc.
// Requires: libsecret-tools package (provides `secret-tool` binary)
// Requires: DBus session bus running (gnome-keyring-daemon)

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type { KeychainStore } from "@publicdomainrelay/app-attest-abc";

// ===========================================================================
// Factory config
// ===========================================================================

export interface GnomeSecretStoreOpts {
  /** Secret collection label. Default: "pdr-compute-provider" */
  collection?: string;
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// Helpers
// ===========================================================================

async function secretTool(
  args: string[],
  logger?: StructuredLoggerInterface,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const cmd = new Deno.Command("secret-tool", {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const out = await cmd.output();
  return {
    code: out.code,
    stdout: new TextDecoder().decode(out.stdout).trim(),
    stderr: new TextDecoder().decode(out.stderr).trim(),
  };
}

async function probeSecretTool(logger?: StructuredLoggerInterface): Promise<boolean> {
  // secret-tool has no --version flag. Probe by checking:
  // 1. Binary exists (try running with no args, exits 2 showing usage = success)
  // 2. DBus session is available (gnome-keyring needs $DBUS_SESSION_BUS_ADDRESS)
  try {
    const { code } = await secretTool([], logger);
    // Exit code 2 = usage displayed (binary exists and works)
    if (code !== 2) {
      logger?.info("secret-tool probe: unexpected exit", { code });
      return false;
    }
    // Check DBus session is reachable
    if (!Deno.env.get("DBUS_SESSION_BUS_ADDRESS") && !Deno.env.get("GNOME_KEYRING_CONTROL")) {
      logger?.info("secret-tool probe: no DBus session or keyring control");
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ===========================================================================
// KeychainStore factory
// ===========================================================================

export function createGnomeKeychainStore(opts: GnomeSecretStoreOpts = {}): KeychainStore & {
  isAvailable(): Promise<boolean>;
} {
  const collection = opts.collection ?? "pdr-compute-provider";
  const logger = opts.logger;
  let avail: boolean | null = null;

  return {
    async isAvailable(): Promise<boolean> {
      if (avail !== null) return avail;
      avail = await probeSecretTool(logger);
      logger?.info(avail ? "gnome-keyring available" : "gnome-keyring not available");
      return avail;
    },

    async save(key: string, value: string): Promise<boolean> {
      if (!(await this.isAvailable())) return false;
      const stdin = new TextEncoder().encode(value);
      // secret-tool store --label=<label> <attribute> <value>
      // We use a single attribute "key" so lookup is: secret-tool lookup key <key>
      const cmd = new Deno.Command("secret-tool", {
        args: ["store", "--label", collection, "key", key],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      });
      const child = cmd.spawn();
      const writer = child.stdin.getWriter();
      await writer.write(stdin);
      await writer.close();
      const out = await child.status;
      if (!out.success) {
        logger?.warn("secret-tool store failed", { key: key.slice(0, 8), code: out.code });
        return false;
      }
      return true;
    },

    load(key: string): string | null {
      // Synchronous load — secret-tool is fast enough for single lookups
      try {
        const cmd = new Deno.Command("secret-tool", {
          args: ["lookup", "key", key],
          stdout: "piped",
          stderr: "piped",
        });
        const out = cmd.outputSync();
        const value = new TextDecoder().decode(out.stdout).trim();
        if (out.code !== 0 || !value) return null;
        return value;
      } catch {
        return null;
      }
    },

    delete(key: string): boolean {
      try {
        const cmd = new Deno.Command("secret-tool", {
          args: ["clear", "key", key],
          stdout: "null",
          stderr: "null",
        });
        const out = cmd.outputSync();
        return out.code === 0;
      } catch {
        return false;
      }
    },
  };
}

/** Quick probe — can we reach secret-tool? */
export async function isGnomeKeyringAvailable(): Promise<boolean> {
  return probeSecretTool();
}
