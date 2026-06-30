# AT Protocol records used by FedProxy

## The `ssh-public-key` record

FedProxy stores SSH public keys as atproto records in your PDS repository. The
record type is likely under a fedproxy-specific NSID. The fedproxy.com web UI
handles record creation, but understanding the structure helps with debugging.

### Record structure (inferred)

```json
{
  "$type": "com.fedproxy.sshPublicKey",
  "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
  "service": "myapp"
}
```

### How FedProxy verifies access

1. You SSH to `fedproxy.com:2222` as `your-handle@fedproxy.com`.
2. fedproxy looks up your handle → resolves to your DID via AT Protocol identity
   resolution (DNS for `did:web`, PLC directory for `did:plc`).
3. fedproxy fetches `ssh-public-key` records from your PDS.
4. It matches the SSH key you presented against the records. If the key is found,
   it checks the `service` field:
   - Exact match against the requested service name → authorized.
   - `"*"` → authorized for any service.
   - `"*.myservice"` → authorized for any subdomain of `myservice`.
5. If authorized, the remote forward is established.

### Record propagation

PDS records are eventually consistent. After creating a record via the fedproxy
web UI, it typically appears within seconds, but can take up to 30 seconds.
If your SSH connection fails with "no matching ssh-public-key record", wait and
retry.

You can verify the record exists by visiting your PDSls link (shown on the
fedproxy success page) or by querying your PDS directly:

```bash
# Using goat CLI
goat xrpc com.atproto.repo.listRecords \
  --repo your-handle \
  --collection com.fedproxy.sshPublicKey
```

### Record lifecycle

- **Creation**: Via fedproxy.com web UI (authenticated with your AT Protocol session).
- **Listing**: The fedproxy UI shows your registered keys.
- **Deletion**: Available through the fedproxy UI (removes the record from your PDS).
- **Multiple keys**: You can register multiple keys, each with different service
  scopes. Use separate keys for separate services or machines.

### Security properties

- The private key never leaves your machine. FedProxy only sees the public key.
- Authentication is cryptographically bound to your AT Protocol identity.
- Your PDS is the source of truth for key authorization — if someone compromises
  your PDS account, they could add their own keys.
- Keys are scoped by service name — a key for `myapp` cannot forward `yourapp`.
  Use `*` scope carefully.
- There is no mechanism to revoke a key other than deleting the record from your
  PDS, which takes effect on the next connection attempt (existing tunnels are
  not terminated).
