// Device key common types.
// Portable — no FFI, no Deno.* APIs, no I/O.

export class DeviceKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeviceKeyError";
  }
}
