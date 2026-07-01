// Apple App Attest common types and C memory helpers.
// Portable — no FFI, no Deno.* APIs, no I/O.

export class AppAttestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppAttestError";
  }
}

const encoder = new TextEncoder();

export function encodeCStr(s: string): Uint8Array {
  return encoder.encode(s + "\0");
}

// NOTE: readCStr requires Deno.UnsafePointerView — it lives here because
// callers across packages use it, but the implementation is Deno-specific.
// It is a pure view over a pointer; no I/O or side effects.
export function readCStr(ptr: Deno.PointerValue | null): string {
  if (ptr === null) return "";
  return new Deno.UnsafePointerView(ptr).getCString();
}

export function allocSizeT(): Uint8Array {
  return new Uint8Array(new BigUint64Array([0n]).buffer);
}

export function readSizeT(buf: Uint8Array): number {
  return Number(new DataView(buf.buffer).getBigUint64(0, true));
}

// Keychain key constants — shared across app-attest and CLI.
export const KC_SESSION_KEY = "oauth-session";
export const KC_DEVICE_KEY_ID = "device-key-id";
