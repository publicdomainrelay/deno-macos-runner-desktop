# FedProxy tunnel setup — step by step

## Prerequisites

- An AT Protocol handle (Bluesky account, or self-hosted PDS with a `did:plc` or `did:web`)
- An SSH client (OpenSSH, built into macOS/Linux/WSL)
- A local service you want to expose (runs on `localhost`, any port)

## Step 1: Generate an SSH key pair

Ed25519 is preferred for fedproxy. You can use an existing key, but a dedicated
key is cleaner:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/fedproxy -C "fedproxy" -N ""
```

This creates `~/.ssh/fedproxy` (private key) and `~/.ssh/fedproxy.pub` (public key).
The `-N ""` creates it without a passphrase — needed for unattended tunnels. If
you add a passphrase, you'll need an SSH agent.

## Step 2: Log in to fedproxy.com

Go to https://fedproxy.com. Enter your AT Protocol handle (e.g. `alice.bsky.social`).
If you're a Bluesky user, choose "Login with Bluesky Social" — this uses OAuth
through your PDS. Self-hosted users can use other options.

Once authenticated, you'll see the key management page.

## Step 3: Register your public key

1. Copy your public key:
   ```bash
   cat ~/.ssh/fedproxy.pub
   ```
2. Paste it into the "Add SSH Public Key" form on fedproxy.com.
3. Enter the **service name** — this is the subdomain prefix for your tunnel.
   Choose from:
   - A specific name like `myapp` → serves at `myapp--<handle>.fedproxy.com`
   - `*` → this key works for any service name you later use
   - `*.myapp` → wildcard subdomain (`dev.myapp--<handle>.fedproxy.com`, etc.)
4. Click Create.

The fedproxy web app writes an `ssh-public-key` record to your PDS using your
authenticated session. You'll see a success message with a PDSls link — click it
to verify the record exists.

## Step 4: Start your local service

Make sure your service is running and listening. For example:

```bash
# Python HTTP server
python3 -m http.server 8080 --bind 127.0.0.1

# Node.js dev server
npm run dev -- --port 3000

# Rails
rails server -p 3000 -b 127.0.0.1
```

The important part: it must be reachable at the address you'll forward to
(usually `127.0.0.1:<port>`).

## Step 5: Start the SSH tunnel

```bash
ssh -NnT -p 2222 \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o PasswordAuthentication=no \
  -o ServerAliveInterval=60 \
  -o ExitOnForwardFailure=yes \
  -i ~/.ssh/fedproxy \
  -R myservice:80:127.0.0.1:8080 \
  your-handle@fedproxy.com
```

### Flag breakdown

| flag | purpose |
|------|---------|
| `-N` | Do not execute a remote command (tunnel only) |
| `-n` | Redirect stdin from /dev/null (for backgrounding) |
| `-T` | Disable pseudo-terminal allocation |
| `-p 2222` | fedproxy's SSH port |
| `-o UserKnownHostsFile=/dev/null` | Skip host key caching (fedproxy hosts are ephemeral) |
| `-o StrictHostKeyChecking=no` | Don't prompt on first connection |
| `-o PasswordAuthentication=no` | Only use key auth |
| `-o ServerAliveInterval=60` | Keep the tunnel alive through NAT/firewall timeouts |
| `-o ExitOnForwardFailure=yes` | Exit immediately if the remote forward fails |
| `-i ~/.ssh/fedproxy` | Path to your private key |
| `-R myservice:80:127.0.0.1:8080` | Remote forward: fedproxy's `myservice:80` → your `127.0.0.1:8080` |

### The remote port is always 80

FedProxy listens for your service name on port 80 internally, then terminates
TLS at the edge. Always use `80` as the remote port in the `-R` argument.

## Step 6: Verify

Open `https://myservice--your-handle.fedproxy.com` in a browser. Replace dots
in your handle with dashes.

Example: handle `alice.bsky.social`, service `myapp` →
`https://myapp--alice-bsky-social.fedproxy.com`

## Running persistently

For a long-running tunnel, use the SSH config snippet in `assets/ssh-config-example`
and combine with a process supervisor.

### With systemd (Linux)

```ini
# /etc/systemd/system/fedproxy-myapp.service
[Unit]
Description=FedProxy tunnel for myapp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -NnT -p 2222 \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o PasswordAuthentication=no \
  -o ServerAliveInterval=60 \
  -o ExitOnForwardFailure=yes \
  -i /home/you/.ssh/fedproxy \
  -R myapp:80:127.0.0.1:8080 \
  your-handle@fedproxy.com
Restart=always
RestartSec=10
User=you

[Install]
WantedBy=multi-user.target
```

Then: `sudo systemctl enable --now fedproxy-myapp`

### With launchd (macOS)

See `assets/ssh-config-example` for a launchd plist.

### With autossh

```bash
autossh -M 0 -NnT -p 2222 \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o PasswordAuthentication=no \
  -o ServerAliveInterval=60 \
  -o ExitOnForwardFailure=yes \
  -i ~/.ssh/fedproxy \
  -R myapp:80:127.0.0.1:8080 \
  your-handle@fedproxy.com
```

`autossh` monitors the connection and restarts it if it dies. `-M 0` disables
the monitoring port (uses ServerAliveInterval instead).
