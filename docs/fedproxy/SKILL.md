---
name: fedproxy
description: >-
  Expose local services to the public internet via SSH tunneling through fedproxy.com,
  authenticated by AT Protocol (Bluesky/Atmosphere) identity. Use this skill whenever
  the user wants to expose a local dev server, set up a public HTTPS endpoint for a
  local service, create an SSH tunnel through fedproxy, register SSH keys on their
  AT Protocol PDS for fedproxy, debug fedproxy tunnel issues, or understand the
  fedproxy service naming convention. Also activate when the user mentions "fedproxy",
  "expose localhost", "public URL for local dev", "ssh tunnel public", or asks how to
  get a public HTTPS URL for a service running on their machine without deploying it.
---

# FedProxy — expose local services via AT Protocol + SSH

FedProxy (https://fedproxy.com) gives every AT Protocol / Bluesky user a way to
expose local services through SSH remote forwarding, served at
`<service>--<your-handle>.fedproxy.com` with automatic HTTPS.

You authenticate with your existing AT Protocol identity (your Bluesky handle or
self-hosted PDS handle). SSH keys are stored as atproto records on your PDS —
fedproxy reads them to authorize tunnels. No separate account, no passwords.

## Mental model

```
 ┌──────────────┐     SSH -R (port 2222)      ┌──────────────┐
 │ your machine │ ◄────────────────────────── │  fedproxy.com │
 │ localhost:8080│                            │              │
 └──────────────┘                             └──────┬───────┘
                                                     │
                                              HTTPS on :443
                                           *.fedproxy.com cert
                                                     │
                                                     ▼
                                            ┌────────────────┐
                                            │ public internet │
                                            │ svc--handle     │
                                            │ .fedproxy.com   │
                                            └────────────────┘
```

1. You add an SSH public key as an atproto record on your PDS (via fedproxy.com
   web UI or direct atproto calls).
2. You start an SSH client connecting to `fedproxy.com` on port `2222` with a
   remote forward (`-R`).
3. fedproxy reads your SSH key, looks up your atproto records by handle, verifies
   the key is authorized for the requested service.
4. Traffic to `https://<service>--<handle>.fedproxy.com` is forwarded through the
   SSH tunnel to your local port.

## Service naming

The hostname is built as: `<service>--<handle>.fedproxy.com`

- Every dot in your handle becomes a dash in the hostname.
- `--` (double dash) separates the service name from the handle.

| handle | service | hostname |
|--------|---------|----------|
| `alice.bsky.social` | `myapp` | `myapp--alice-bsky-social.fedproxy.com` |
| `bob.example.com` | `api` | `api--bob-example-com.fedproxy.com` |
| `carol.dev` | `dev` | `dev--carol-dev.fedproxy.com` |

### Service field values (when registering a key)

- `"my-service"` — a single named service.
- `"*"` — wildcard: this key is valid for ALL your services (an authorization
  wildcard, not a hostname wildcard).
- `"*.my-service"` — subdomain wildcard: serves any `anything.my-service--<handle>.fedproxy.com`.
  This variant gets its own TLS certificate issued on demand (not using the shared
  `*.fedproxy.com` wildcard cert).

### TLS

Every service rides the shared `*.fedproxy.com` wildcard certificate, so HTTPS
works the moment you connect — no per-service certificate issuance. The exception
is the `*.my-service` subdomain wildcard pattern, which gets its own certificate.

## Workflow

Read `references/tunnel-setup.md` for the step-by-step, but the outline:

1. **Log in** at https://fedproxy.com with your AT Protocol handle (Bluesky or
   self-hosted PDS).
2. **Generate or select an SSH key pair.** Ed25519 recommended:
   `ssh-keygen -t ed25519 -f ~/.ssh/fedproxy -C "fedproxy"`
3. **Register the public key** via the fedproxy web UI (it writes an
   `ssh-public-key` record to your PDS), specifying the service name.
4. **Start the tunnel:**
   ```
   ssh -NnT -p 2222 \
     -o UserKnownHostsFile=/dev/null \
     -o StrictHostKeyChecking=no \
     -o PasswordAuthentication=no \
     -i ~/.ssh/fedproxy \
     -R myservice:80:127.0.0.1:8080 \
     your-handle@fedproxy.com
   ```
5. **Access** `https://myservice--your-handle.fedproxy.com`

### The `-R` argument decoded

`-R myservice:80:127.0.0.1:8080`

| part | meaning |
|------|---------|
| `myservice` | service name (must match what you registered the key for) |
| `80` | remote port on fedproxy's side (always 80; fedproxy terminates TLS) |
| `127.0.0.1:8080` | where your local service is listening |

Your local service gets plain HTTP — fedproxy handles TLS termination. Your app
does not need to speak HTTPS.

### Key scope checking

A key registered for service `myapp` can only forward `myapp`. A key registered
for `*` can forward any of your services. A key registered for `*.myapp` can
forward `foo.myapp`, `bar.myapp`, etc.

## Troubleshooting quick reference

See `references/troubleshooting.md` for full debugging.

- **Connection refused on port 2222**: fedproxy SSH server may be restarting; retry.
- **"Permission denied (publickey)"**: Key not registered, or registered for a
  different service. Re-check the fedproxy web UI.
- **"no matching ssh-public-key record"**: PDS record may not have propagated yet.
  Wait ~30 seconds and retry. Check your PDSls link from the success page.
- **HTTPS not working**: Confirm the service name in the hostname matches exactly.
  Dots vs dashes in the handle part are a common mistake.
- **Local service not receiving requests**: Check your `-R` bind address. Use
  `127.0.0.1` not `localhost` if your service binds IPv4 only. Use `-v` on the
  SSH command for verbose debug output.

## Reference files

- `references/tunnel-setup.md` — complete step-by-step guide
- `references/atproto-records.md` — the `ssh-public-key` record schema and how
  fedproxy uses your PDS
- `assets/ssh-config-example` — SSH config snippet for persistent tunnels
