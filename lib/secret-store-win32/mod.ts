// @ts-nocheck — Deno FFI Deno.UnsafePointerView not in type declarations
// Secret store — Windows Credential Manager via advapi32.dll FFI.
// Implements KeychainStore from app-attest-abc.
//
// DPAPI-encrypted per-user store. No external dependencies.
// Same FFI pattern as app-attest-darwin: lazy DLL load, sync wrappers.
//
// Probe (isAvailable) does a test write — catches ERROR_NO_SUCH_LOGON_SESSION
// (1312) from SSH sessions without full Windows logon.

import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type { KeychainStore } from "@publicdomainrelay/app-attest-abc";

// ===========================================================================
// Factory config
// ===========================================================================

export interface Win32SecretStoreOpts {
  /** Credential target prefix. Default: "PDREXT:" */
  prefix?: string;
  logger?: StructuredLoggerInterface;
}

// ===========================================================================
// FFI
// ===========================================================================

const CRED_TYPE_GENERIC = 1;

let dll: Deno.DynamicLibrary<{
  CredWriteW: { parameters: ["pointer", "u32"]; result: "i32" };
  CredReadW: { parameters: ["pointer", "u32", "u32", "pointer"]; result: "i32" };
  CredDeleteW: { parameters: ["pointer", "u32", "u32"]; result: "i32" };
  CredFree: { parameters: ["pointer"]; result: "void" };
}> | null = null;
let dllError: string | null = null;

function ensureDll(logger?: StructuredLoggerInterface): void {
  if (dll || dllError !== null) return;
  try {
    dll = Deno.dlopen("advapi32.dll", {
      CredWriteW: { parameters: ["pointer", "u32"], result: "i32" },
      CredReadW: { parameters: ["pointer", "u32", "u32", "pointer"], result: "i32" },
      CredDeleteW: { parameters: ["pointer", "u32", "u32"], result: "i32" },
      CredFree: { parameters: ["pointer"], result: "void" },
    });
    logger?.info("advapi32.dll loaded");
  } catch (e) {
    dllError = e instanceof Error ? e.message : String(e);
    logger?.info("advapi32.dll not available", { error: dllError });
  }
}

// ===========================================================================
// Wide string helpers
// ===========================================================================

const encoder = new TextEncoder();

function toWideStr(s: string): Uint8Array {
  const chars: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    chars.push(code & 0xff, (code >> 8) & 0xff);
  }
  chars.push(0, 0);
  return new Uint8Array(chars);
}

// ===========================================================================
// CREDENTIALW struct builder (x86_64 Windows layout, 80 bytes)
// ===========================================================================
//
// Offset  Size  Field
// 0       4     Flags (u32)
// 4       4     Type (u32)
// 8       8     TargetName (pointer)
// 16      8     Comment (pointer)
// 24      8     LastWritten (u64)
// 32      4     CredentialBlobSize (u32)
// 36      4     (padding)
// 40      8     CredentialBlob (pointer)
// 48      4     Persist (u32)
// 52      4     (padding)
// 56      8     Attributes (pointer)
// 64      8     TargetAlias (pointer)
// 72      8     UserName (pointer)
// Total: 80 bytes

const CREDENTIALW_SIZE = 80;

function buildCredentialW(targetWStr: Uint8Array, blob: Uint8Array): Uint8Array {
  const buf = new Uint8Array(CREDENTIALW_SIZE);
  const dv = new DataView(buf.buffer);

  const targetAddr = Deno.UnsafePointer.value(Deno.UnsafePointer.of(targetWStr));
  const blobAddr = Deno.UnsafePointer.value(Deno.UnsafePointer.of(blob));

  dv.setUint32(0, 0, true);                        // Flags
  dv.setUint32(4, CRED_TYPE_GENERIC, true);        // Type
  dv.setBigUint64(8, BigInt(targetAddr), true);    // TargetName
  dv.setBigUint64(16, 0n, true);                   // Comment
  dv.setBigUint64(24, 0n, true);                   // LastWritten
  dv.setUint32(32, blob.length, true);             // CredentialBlobSize
  dv.setBigUint64(40, BigInt(blobAddr), true);     // CredentialBlob
  dv.setUint32(48, 1, true);                       // Persist = CRED_PERSIST_SESSION
  dv.setBigUint64(56, 0n, true);                   // Attributes
  dv.setBigUint64(64, 0n, true);                   // TargetAlias
  dv.setBigUint64(72, 0n, true);                   // UserName

  return buf;
}

// ===========================================================================
// KeychainStore factory
// ===========================================================================

export function createWin32KeychainStore(opts: Win32SecretStoreOpts = {}): KeychainStore & {
  isAvailable(): boolean;
} {
  const prefix = opts.prefix ?? "PDREXT:";
  const logger = opts.logger;
  let probed = false;
  let probeResult = false;

  function targetName(key: string): string {
    return `${prefix}${key}`;
  }

  return {
    isAvailable(): boolean {
      if (probed) return probeResult;
      ensureDll(logger);
      if (!dll) { probed = true; probeResult = false; return false; }

      // Real probe: try writing a test credential then delete it.
      // ERROR_NO_SUCH_LOGON_SESSION (1312) = no Windows logon session.
      const testKey = `${prefix}__probe__`;
      const tgt = toWideStr(testKey);
      const blob = new Uint8Array(4);
      const cred = buildCredentialW(tgt, blob);

      try {
        const result = dll.symbols.CredWriteW(
          Deno.UnsafePointer.of(cred), 0,
        );
        if (result !== 0) {
          dll.symbols.CredDeleteW(Deno.UnsafePointer.of(tgt), CRED_TYPE_GENERIC, 0);
          probeResult = true;
        } else {
          probeResult = false;
        }
      } catch {
        probeResult = false;
      }
      probed = true;
      if (logger) {
        logger.info(probeResult
          ? "win32-credman available"
          : "win32-credman not available (no logon session), falling back");
      }
      return probeResult;
    },

    async save(key: string, value: string): Promise<boolean> {
      if (!probeResult) return false;
      ensureDll(logger);
      if (!dll) return false;

      const tgt = toWideStr(targetName(key));
      const blob = encoder.encode(value);
      const cred = buildCredentialW(tgt, blob);

      try {
        const result = dll.symbols.CredWriteW(
          Deno.UnsafePointer.of(cred), 0,
        );
        return result !== 0;
      } catch (e) {
        logger?.warn("CredWriteW failed", { key: key.slice(0, 8), error: String(e) });
        return false;
      }
    },

    load(key: string): string | null {
      if (!probeResult) return null;
      ensureDll(logger);
      if (!dll) return null;

      const tgt = toWideStr(targetName(key));
      const outPtrBuf = new BigUint64Array(1);
      const outPtrBufBytes = new Uint8Array(outPtrBuf.buffer);

      try {
        const result = dll.symbols.CredReadW(
          Deno.UnsafePointer.of(tgt), CRED_TYPE_GENERIC, 0,
          Deno.UnsafePointer.of(outPtrBufBytes),
        );
        if (result === 0) return null;

        const credPtrVal = outPtrBuf[0];
        if (credPtrVal === 0n) return null;

        const credPtr = Deno.UnsafePointer.create(Number(credPtrVal));
        const credView = new Deno.UnsafePointerView(credPtr);

        const blobSize = Number(credView.getBigUint64(32) & 0xFFFFFFFFn);
        const blobPtrVal = credView.getBigUint64(40);
        if (blobSize === 0 || blobPtrVal === 0n) {
          dll.symbols.CredFree(credPtr);
          return null;
        }

        const blobView = new Deno.UnsafePointerView(
          Deno.UnsafePointer.create(Number(blobPtrVal)),
        );
        const blobBuf = new Uint8Array(blobSize);
        blobBuf.set(new Uint8Array(blobView.getArrayBuffer(blobSize)));

        const value = new TextDecoder().decode(blobBuf);
        dll.symbols.CredFree(credPtr);
        return value;
      } catch (e) {
        logger?.warn("CredReadW failed", { key: key.slice(0, 8), error: String(e) });
        return null;
      }
    },

    delete(key: string): boolean {
      if (!probeResult) return false;
      ensureDll(logger);
      if (!dll) return false;

      const tgt = toWideStr(targetName(key));
      try {
        return dll.symbols.CredDeleteW(
          Deno.UnsafePointer.of(tgt), CRED_TYPE_GENERIC, 0,
        ) !== 0;
      } catch (e) {
        logger?.warn("CredDeleteW failed", { key: key.slice(0, 8), error: String(e) });
        return false;
      }
    },
  };
}

export function isWin32CredManAvailable(): boolean {
  // Just check if DLL loads — real probe happens in isAvailable()
  try {
    ensureDll();
    return dll !== null;
  } catch {
    return false;
  }
}
