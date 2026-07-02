// BadgeBlue Keys ATProto implementation — creates and manages key→DID
// association records on the user's PDS. Portable: Web Crypto + fetch only.
// No attestation dependency — rkey derived from sha256(did + keyId).

import {
  BADGE_BLUE_KEYS_NSID, base58btcEncode,
  type BadgeBlueKeysSession,
} from "@publicdomainrelay/badge-blue-keys-common";
import type { AssociationService } from "@publicdomainrelay/badge-blue-keys-abc";
import { sha256, createDpopProof } from "@publicdomainrelay/atproto-oauth-fetch";

const enc = new TextEncoder();

// ===========================================================================
// AssociationService factory
// ===========================================================================

export function createAssociationService(): AssociationService {
  let cachedRkey: string | null = null;
  let cachedKey: string | null = null;

  return {
    async computeRkey(persistentKeyId: string, did: string): Promise<string> {
      const cacheKey = `${did}:${persistentKeyId}`;
      if (cachedRkey && cachedKey === cacheKey) return cachedRkey;
      if (!persistentKeyId || !did) throw new Error("not ready");

      // Deterministic rkey from sha256(did + ":" + keyId)
      const hash = await sha256(enc.encode(`${did}:${persistentKeyId}`));
      // Take first 24 bytes, base58btc encode, use first 32 chars as rkey
      const rkeyRaw = base58btcEncode(hash.slice(0, 24));
      const rkey = rkeyRaw.slice(0, 32);

      cachedKey = cacheKey;
      cachedRkey = rkey;
      return rkey;
    },

    async createRecord(
      session: BadgeBlueKeysSession,
      persistentKeyId: string,
      service = "*",
    ): Promise<string> {
      if (!session || !persistentKeyId) throw new Error("not ready");
      const { did, pds, accessJwt, dpopKeyPair, dpopPublicJwk } = session;
      const rkey = await this.computeRkey(persistentKeyId, did);
      const createEndpoint = `${pds}/xrpc/com.atproto.repo.createRecord`;
      const body = JSON.stringify({
        repo: did,
        collection: BADGE_BLUE_KEYS_NSID,
        rkey,
        record: {
          $type: BADGE_BLUE_KEYS_NSID,
          keyId: persistentKeyId,
          challenge: did,
          service,
          createdAt: new Date().toISOString(),
        },
      });

      const doCreate = async (nonce: string | null): Promise<Response> => {
        const dpopProof = await createDpopProof(
          dpopKeyPair, dpopPublicJwk, "POST", createEndpoint, nonce ?? undefined, accessJwt,
        );
        return fetch(createEndpoint, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "Authorization": `DPoP ${accessJwt}`,
            "DPoP": dpopProof,
          },
          body,
        });
      };

      let res = await doCreate(null);
      if (!res.ok) {
        const errBody = await res.text();
        if (errBody.includes("use_dpop_nonce")) {
          const nonce = res.headers.get("DPoP-Nonce");
          if (!nonce) throw new Error(`createRecord: ${res.status} ${errBody}`);
          res = await doCreate(nonce);
        } else {
          throw new Error(`createRecord: ${res.status} ${errBody}`);
        }
      }
      if (!res.ok) { const eb = await res.text(); throw new Error(`createRecord: ${res.status} ${eb}`); }
      const cd = await res.json();
      return cd.uri as string;
    },

    async findOrCreateRecord(
      session: BadgeBlueKeysSession,
      persistentKeyId: string,
    ): Promise<string | null> {
      if (!session || !persistentKeyId) return null;
      const { did, pds, accessJwt, dpopKeyPair, dpopPublicJwk } = session;
      try {
        const rkey = await this.computeRkey(persistentKeyId, did);
        const endpoint = `${pds}/xrpc/com.atproto.repo.getRecord?repo=${did}&collection=${BADGE_BLUE_KEYS_NSID}&rkey=${rkey}`;

        const doGet = async (nonce: string | null): Promise<Response> => {
          const dpopProof = await createDpopProof(
            dpopKeyPair, dpopPublicJwk, "GET", endpoint, nonce ?? undefined, accessJwt,
          );
          return fetch(endpoint, {
            headers: { "Authorization": `DPoP ${accessJwt}`, "DPoP": dpopProof },
          });
        };

        let res = await doGet(null);
        if (!res.ok) {
          const probeBody = await res.clone().text();
          if (probeBody.includes("use_dpop_nonce")) {
            const nonce = res.headers.get("DPoP-Nonce");
            if (nonce) res = await doGet(nonce);
          }
        }

        if (res.ok) {
          const data = await res.json();
          return data.uri || null;
        }
        const errBody = await res.json().catch(() => ({}));
        if (res.status === 404 || errBody.error === "RecordNotFound") {
          return this.createRecord(session, persistentKeyId);
        }
        console.error("badge-blue-keys: getRecord failed", res.status, JSON.stringify(errBody));
        return null;
      } catch (e) {
        console.error("badge-blue-keys: findOrCreateRecord threw", String(e));
        return null;
      }
    },
  };
}
