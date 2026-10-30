# idaas

[![docker](https://github.com/tayyebi/idaas/actions/workflows/docker.yml/badge.svg)](https://github.com/tayyebi/idaas/actions/workflows/docker.yml)

A minimal OpenID Connect provider written in C — with one difference: **by
default it has no user database**. Its users are the machine's Linux
accounts, verified through PAM (`pam_unix`), so every hash scheme your host
uses keeps working: yescrypt (Debian 12 / Ubuntu 22.04+ / Arch defaults),
sha512crypt, sha256crypt, bcrypt, and friends. On top of that there is an
optional **admin API** (gated Postfix-`mynetworks`-style) that manages a
small set of idaas-local users — handy for accounts that shouldn't exist on
the host.

Everything ships in a multi-stage Docker image so nothing but Docker ever
runs on the host, and the container only ever sees files under `./data`.

```
 relying party               your reverse proxy            idaas container
 (Grafana, Gitea, ...)  ──►  (TLS termination)     ──►  ┌─────────────────────────────┐
                                                        │ /etc/passwd ◄── data/etc/passwd (ro)
                                                        │ /etc/shadow ◄── data/etc/shadow (ro)
                                                        │ /etc/group  ◄── data/etc/group  (ro)
                                                        │ /data       ◄── data           (rw: signing keys,
                                                        │                                │    managed users)
                                                        └─────────────────────────────┘
```

The passwd/shadow/group files are **snapshots** copied into `./data/etc` by
`make sync-users`. The container never mounts the host's live `/etc` — even
a fully compromised container only sees a stale, read-only copy.

## Supported OIDC surface

Deliberately small and modern:

- Authorization Code flow with **PKCE (S256)** — required for public clients
- Grants: `authorization_code`, `refresh_token` (rotating)
- RS256 ID tokens and access tokens (JWT), published JWKS, discovery,
  webfinger, `/userinfo`, RP-initiated logout
- Client auth: `client_secret_basic`, `client_secret_post`, `none`
- Scopes: `openid`, `profile` (name from the GECOS field,
  `preferred_username`), `email` (`user@IDAAS_EMAIL_DOMAIN`),
  `groups` (names from `/etc/group`)

Not supported (on purpose): implicit/hybrid flows, device flow, consent
screen (all registered clients are first-party).

## Sign-in flow & the account chooser

`/authorize` never signs a user in silently — the flow always stops at an
explicit confirmation page:

1. **No signed-in accounts** → the login form (Linux account or managed
   user, PAM-verified).
2. **One or more remembered accounts** → the **account chooser**. Every
   account signed in on this browser is listed — with a single account too,
   so it is confirmed rather than assumed — plus a **"Use another account"**
   link to the login form. Picking an account mints the code and redirects
   back to the application; signing in as a new account does the same right
   after login.

Accounts stay signed in side by side: each login sets a per-account cookie
(`idaas_acct_<hash>`) alongside the active-session cookie `idaas_sid`, and
the chooser lists them all. Remembered accounts idle out on the same
`IDAAS_SESSION_IDLE` clock (background accounts are validated read-only, so
listing them never keeps them alive), expire with `IDAAS_SESSION_ABS`, and
are capped at 5 per browser. `/logout` signs out **only the active
account** — the other remembered accounts stay on the chooser.

## Quick start

On the Linux host that owns the accounts (needs `sudo` once, to read
`/etc/shadow`):

```sh
make sync-users        # snapshots /etc/{passwd,shadow,group} into ./data/etc
$EDITOR data/clients.conf   # created from clients.example.conf
docker compose up -d   # pulls ghcr.io/tayyebi/idaas:latest (see note below)
```

The compose file runs the published image from GHCR with
`pull_policy: always`, so `docker compose up -d` (or `make update`) always
runs the newest version. Note: new GHCR packages start **private** — after
the first CI push, make the package public once (GitHub → Packages →
idaas → Package settings), or `docker login ghcr.io` with a token that has
`read:packages` on every deployment host. To run a locally built image
instead: `IDAAS_IMAGE=idaas:latest docker compose up -d`.

Optionally enable the admin API (for idaas-local "managed" users) by
uncommenting `IDAAS_ADMIN_NETWORKS` / `IDAAS_ADMIN_TOKEN` in
`docker-compose.yml` — see [Managed users & the admin
API](#managed-users--the-admin-api) before you do.

Point your reverse proxy at `127.0.0.1:8080`. **The issuer URL must match
the external HTTPS address** — idaas speaks plain HTTP by design.

Caddy:

```
sso.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
server {
    server_name sso.example.com;
    listen 443 ssl;
    # ssl_certificate ...; ssl_certificate_key ...;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

With a proxy in front, set `IDAAS_TRUST_PROXY=1` so rate limiting and audit
logs use the real client IP.

Example: Grafana

```ini
[auth.generic_oauth]
name = idaas
enabled = true
client_id = grafana
client_secret = <same as data/clients.conf>
scopes = openid profile email groups
auth_url = https://sso.example.com/authorize
token_url = https://sso.example.com/token
api_url = https://sso.example.com/userinfo
auto_login = true
```

## Configuration

Environment variables (`IDAAS_*`):

| Variable | Default | Meaning |
|---|---|---|
| `IDAAS_ISSUER` | — (required) | External base URL, e.g. `https://sso.example.com` |
| `IDAAS_LISTEN` | `:8080` | Listen spec: `:8080` or `127.0.0.1:8080` |
| `IDAAS_DATA_DIR` | `/data` | Writable dir for signing keys |
| `IDAAS_CLIENTS_FILE` | `/data/clients.conf` | Client registry |
| `IDAAS_EMAIL_DOMAIN` | `localhost` | Domain for synthesized `email` claims |
| `IDAAS_UID_MIN` / `IDAAS_UID_MAX` | `1000` / `60000` | Only accounts in this uid range may log in |
| `IDAAS_SESSION_IDLE` / `IDAAS_SESSION_ABS` | `3600` / `28800` | Session idle / absolute timeouts (s) |
| `IDAAS_ACCESS_TTL` / `IDAAS_REFRESH_TTL` | `600` / `2592000` | Token lifetimes (s) |
| `IDAAS_TRUST_PROXY` | `0` | Honor `X-Forwarded-For` |
| `IDAAS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `IDAAS_ADMIN_NETWORKS` | *(unset)* | CIDR allowlist for the admin API (see below); unset = admin API disabled |
| `IDAAS_ADMIN_TOKEN` | *(unset)* | Optional bearer token required by the admin API |
| `IDAAS_MANAGED_USERS_FILE` | `/data/managed-users` | Store for API-managed users |
| `IDAAS_HASH_METHOD` | `SHA512` | Password hash for managed users (`SHA512`, `SHA256`) |
| `IDAAS_MANAGED_UID_BASE` | `60001` | Base for virtual uids assigned to managed users |

`data/clients.conf` — one INI section per client:

```ini
[my-app]
secret = long-random-string     # or the bare flag `public` (PKCE required)
redirect_uri = https://my-app.example.com/oauth/callback
post_logout_redirect_uri = https://my-app.example.com/signed-out   # optional
scope = openid profile email groups
```

`redirect_uri` may appear multiple times; both URI lists are matched
exactly. `post_logout_redirect_uri` entries are the only targets
RP-initiated logout (`/logout?post_logout_redirect_uri=…`) will bounce
the browser back to — a registered `redirect_uri` is deliberately NOT
accepted there; without a match the user simply gets the signed-out page.

## Managed users & the admin API

idaas knows two kinds of users:

1. **Linux accounts** — the host's users via the read-only snapshots.
   Created with `useradd`/`passwd` on the host, verified via PAM.
2. **Managed users** — idaas-local accounts that exist only inside
   `./data/managed-users` (never on the host), verified locally with
   crypt(3) (`$6$` sha512crypt by default). On a name collision, the
   managed entry wins.

Managed users are administered over the REST API under `/api/users`:

| Method & path | Purpose |
|---|---|
| `GET /api/users` | List (no password hashes in the response) |
| `POST /api/users` | Create (form: `username`, `password`, `name`, `email`, `groups`) |
| `GET /api/users/<name>` | Fetch one |
| `PUT/PATCH /api/users/<name>` | Update any of: `password`, `name`, `email`, `groups`, `disabled=0|1` |
| `DELETE /api/users/<name>` | Delete |

```sh
# create a user
curl -H "Authorization: Bearer $TOKEN" \
     --data-urlencode "username=dan" \
     --data-urlencode "password=dan-pass-99" \
     --data-urlencode "name=Dan M" \
     --data-urlencode "email=dan@corp.example" \
     --data-urlencode "groups=dev,ops" \
     https://sso.example.com/api/users

# rotate a password / disable / delete
curl -H "Authorization: Bearer $TOKEN" --data-urlencode "password=new-pass" -X PUT .../api/users/dan
curl -H "Authorization: Bearer $TOKEN" --data "disabled=1"            -X PUT .../api/users/dan
curl -H "Authorization: Bearer $TOKEN" -X DELETE .../api/users/dan
```

**The mynetworks gate.** Like Postfix's `mynetworks`, the admin API is only
reachable from networks you explicitly trust, configured with
`IDAAS_ADMIN_NETWORKS` (comma-separated CIDRs, IPv4 and IPv6):

```
IDAAS_ADMIN_NETWORKS=127.0.0.0/8,192.168.1.0/24
IDAAS_ADMIN_TOKEN=<long random string>   # strongly recommended as a 2nd factor
```

- No networks configured ⇒ **every** `/api` request is refused with 403.
- Requests from outside the allowlist get 403 *before* any other check.
- If `IDAAS_ADMIN_TOKEN` is set, callers must also present
  `Authorization: Bearer <token>` (compared in constant time).
- All admin operations are audit-logged (`admin-user` events).

**Docker networking caveat (read this):** connections that arrive through
the published port or your reverse proxy appear to come from the Docker
bridge network (usually `172.16.0.0/12`) — the guest cannot see the real
client IP unless a proxy forwards `X-Forwarded-For` and you set
`IDAAS_TRUST_PROXY=1`. When allowing `172.16.0.0/12`, *every container* on
the default bridge can reach the admin API — prefer a dedicated compose
network with a narrow subnet (e.g. `172.28.0.0/29`) and allowlist exactly
that, or front the API with a proxy that enforces authentication, and set
the token.

## Security model

- **Host isolation**: bind mounts originate only under `./data`; the three
  account files are mounted `:ro`; no compiler or toolchain ever runs on the
  host (`make build` / `make run` wrap Docker). The `./data` volume is
  writable because idaas persists its RSA signing keys and the managed-user
  store there — those are the only locations the process writes to.
- **uid gate**: accounts outside `IDAAS_UID_MIN..IDAAS_UID_MAX` (default
  1000–60000) are rejected before PAM is even invoked, so snapshots of
  system accounts can't log in.
- **Same error for everything**: unknown user, wrong password, and locked
  accounts all produce the identical "Invalid username or password."
- **Rate limiting**: 5 failed logins per username and per IP escalate from
  a 15-second lockout up to 15 minutes.
- **Nothing secret at rest in memory**: session ids, authorization codes,
  and refresh tokens are stored keyed by their SHA-256; CSRF tokens and
  client secrets are compared in constant time.
- **Session hygiene**: HttpOnly `SameSite=Lax` cookies (with `Secure` when
  the issuer is HTTPS), a brand-new session token at every login (fixation
  defense that still leaves the previously active account's session alive),
  CSRF-protected login and account-chooser forms, idle + absolute expiry.
  The chooser accepts an account only when the browser's own cookies prove
  its session — a forged or cross-site form cannot name someone else's.
- **PKCE everywhere**: public clients must use S256; codes are single-use,
  60-second TTL, bound to client + redirect_uri + challenge.
- **Hardened container**: all capabilities dropped, `no-new-privileges`,
  pids/memory limits, published only on loopback (see `docker-compose.yml`).
  Running as uid 0 inside the container is required solely to read the
  0600 shadow snapshot — with no capabilities, plain owner-read is all it
  can do.
- Passwords are never logged or written anywhere.

## Keeping users fresh

`make sync-users` only changes things when a snapshot actually differs
(it prints `changed`/`unchanged`). A cron entry that restarts the container
only when needed:

```cron
*/15 * * * * root cd /srv/idaas && sh scripts/sync-users.sh 2>/dev/null | grep -q changed && docker restart idaas
```

Note the trade-off: idaas keeps sessions and refresh tokens in memory, so a
restart logs everyone out. Sign-in again is one password prompt. (Signing
keys persist in `./data`, so tokens issued before a restart still verify.)

Managed (API-created) users don't need any of this: they live in
`./data/managed-users`, and every admin-API change takes effect
immediately — no snapshot, no restart. They are never synced to or from the
host.

## Development

```sh
make docker-build    # build the runtime image locally (tag: idaas)
make docker-test     # run the unit + PAM tests inside the docker "test" stage
make docker-smoke    # full end-to-end flow against fixture users (in docker),
                     # including the admin API and a managed-user lifecycle
make run             # docker compose up (pulls ghcr.io/tayyebi/idaas:latest)
make update          # docker compose pull && up -d — refresh to newest image
make sync-users      # snapshot host accounts into ./data (sudo)
```

**CI** (`.github/workflows/docker.yml`): every PR and push builds the test
stage (unit + PAM tests run at build time) and runs the full smoke test.
Pushes to `main` publish `ghcr.io/tayyebi/idaas:latest` (plus a `sha-…`
tag) for `linux/amd64` and `linux/arm64`; `v*` tags additionally publish
version tags (`1.2.3`, `1.2`).

The plain `make` targets (`all`, `unit`, `pamtest`) are what the Docker
stages run; they need `gcc`, `libssl-dev`, `libpam0g-dev`,
`libmicrohttpd-dev` if you insist on building outside Docker.

Project layout: `src/*.c` (one module per concern), `web/` (login/choose/error
pages, embedded at build time via `scripts/embed.sh`), `tests/` (assert-based
unit tests + PAM integration test with fixture users created inside the
image), `pam/idaas` (PAM policy baked into the image).

## Limitations & roadmap

- Single process, in-memory sessions/codes/refresh tokens (restart logs
  users out; keys persist so issued tokens keep verifying). Managed-user
  records do persist (up to 1024 accounts).
- No consent screen — all registered clients are first-party.
- Single signing key; rotation means deleting `./data/keys` and restarting.
- Future: refresh-token persistence, consent screen, TOTP via a PAM module
  (drops in without code changes — that's the PAM payoff), per-group login
  allowlists.

## Warning

`./data` contains `/etc/shadow` hashes and client secrets. It is in
`.gitignore` — never commit, copy, or back it up unencrypted.
