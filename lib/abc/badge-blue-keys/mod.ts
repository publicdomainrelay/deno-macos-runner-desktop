// BadgeBlue Keys ABC — pure interface for attestation→ATProto record binding.
// Zero I/O, zero side effects.

import type { BadgeBlueKeysSession } from "@publicdomainrelay/badge-blue-keys-common";

export interface AssociationService {
  /** Derive the deterministic record rkey from a DeviceCheck attestation. */
  computeRkey(
    persistentKeyId: string,
    did: string,
  ): Promise<string>;

  /** Create a badgeBlueKeys record on the user's PDS. Returns the AT URI. */
  createRecord(
    session: BadgeBlueKeysSession,
    persistentKeyId: string,
    service?: string,
  ): Promise<string>;

  /** Find existing association record for this key, or create one. */
  findOrCreateRecord(
    session: BadgeBlueKeysSession,
    persistentKeyId: string,
  ): Promise<string | null>;
}
