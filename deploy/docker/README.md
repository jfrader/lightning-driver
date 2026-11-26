# Docker install

Requires Docker Engine with Compose v2 or later, Git, internet access for the
source build, and enough disk/RAM to compile Rust and the UI. No host Rust or
Node installation is needed. Run these commands from a checkout of this repo:

```sh
cd deploy/docker
install -d -m 0700 state
export APP_UID=$(id -u) APP_GID=$(id -g)
docker compose up -d --build
```

Do not run the app as UID 0. The defaults are UID/GID 1000; if your account uses
different IDs, keep those exports for subsequent Compose commands or put
`APP_UID` and `APP_GID` in `.env`. The bind-mounted `state` directory must be
owned by that UID and must not be group/world writable. Docker must not create
it for you as root.

Open **http://localhost:4400** (not an IP address: the passkey hostname is
`localhost`). On a remote host use SSH forwarding, for example
`ssh -L 4400:127.0.0.1:4400 user@host`, then open that same localhost URL.
No node is needed to open the UI. Only the UI/proxy port is published, on host
loopback. API and proxy share one container; the API listens on 127.0.0.1:8080
inside it. Do not publish that port or use host networking.

## State and nodes

The first start creates `state/config.toml` from `config.localhost.toml` without
replacing an existing file. Config, SQLite journal, invoice key and node
credentials all belong under `state/` (mounted at `/state`). Relative paths in
config resolve there. Do not change the API bind.

To add nodes, stop the app with `docker compose stop app`, edit
`state/config.toml`, remove `nodes = []` and add entries from the repository's
root README. Copy credentials into `state/` with mode 0600, owned by `APP_UID`;
their parent directories must not be symlinks or group/world writable.
Public certificates may be root-owned. Restart with `docker compose up -d`.
Inside Docker, `127.0.0.1` means this container, not the host or a node's
container; use an HTTPS endpoint reachable from the app container.

Enroll a sign-in method while the app is running:

```sh
docker compose exec app /opt/lightning-driver/api-server auth enrollment --config /state/config.toml
```

Paste the printed one-use token into the UI. Treat it as a secret.

```sh
docker compose ps
docker compose logs -f app
docker compose down
```

`down` stops containers but keeps state. The healthcheck checks the UI and the
API's typed root response through the proxy without creating sign-in sessions;
`healthy` does not certify node health.

## Upgrade and backup

Back up the **whole** state directory, including the original invoice key and
credentials, while stopped. Keep the archive private (it contains secrets):

```sh
docker compose stop app
(umask 077; tar -czf lightning-driver-state.tar.gz state)
docker compose start app
```

Store the archive off-host. Restore into a stopped installation with the same
UID/GID, preserving modes; never run two copies against the same database.

To upgrade, back up first, then run `git pull --ff-only` from the repository
checkout and `docker compose up -d --build` from this directory. Existing config
and keys are kept. The image pins UI commit
`2940f568256a4eb04abd08ce4ed5c0863c585b9c`; to select a reviewed replacement:
`docker compose build --build-arg UI_COMMIT=<full-commit> app`, then
`docker compose up -d --no-build`.

## HTTPS with a real domain

The optional `https` profile runs Caddy; it is off by default. Only enable it
when you intend to expose this installation. Point your domain's DNS at the
host and permit inbound TCP 80/443. Caddy obtains and renews certificates.

1. Start once locally to create config, then `docker compose stop app`.
2. Copy `.env.example` to `.env`. Set `LIGHTNING_HOST=manager.example.com` to
   your exact domain (no scheme/port/path), and set the state owner's UID/GID.
3. Replace these three fields in `state/config.toml` under the existing `[api]`:

   ```toml
   public_origin = "https://manager.example.com"
   rp_id = "manager.example.com"
   allow_insecure_loopback = false
   ```

4. Run `docker compose --profile https up -d --build` and open your HTTPS URL.

Origin and rp_id must name the same exact host. A hostname change requires
enrolling a passkey for that hostname. Keep `bind = "127.0.0.1:8080"`.
Caddy forwards Host and Origin unchanged and caps request bodies at 128KB.
Its certificates live in the `caddy_data` volume; do not remove that volume
during upgrades. Use `docker compose --profile https down` to stop both services.

By default the UI proxy does not trust forwarded client-IP headers; API
admission limits share one socket identity. Do not trust an entire Docker
subnet or arbitrary browser-supplied forwarding headers.

The simple container shares one UID between API and UI. For separate service
accounts and artifact verification, use the hardened `deploy/install.sh` path.
