# Simple systemd install (no Docker)

This is the simple, single-account path. `deploy/install.sh` remains the
hardened path with separate API/UI accounts and verified artifact manifests.
Do not run both against the same state directory.

Requires systemd, Bash, Node 24, Git, Rust/Cargo (see the root README), a C
toolchain, `protoc`, `pkg-config`, OpenSSL development headers and runtime
libraries. Build as your own user from the backend repository root:

```sh
cargo build --locked --release -p lightning-driver-api
git clone https://github.com/jfrader/lightning-driver-ui ui-build
git -C ui-build checkout --detach 2940f568256a4eb04abd08ce4ed5c0863c585b9c
(cd ui-build && npm ci && npm run build)
```

Copy the built files and the shared supervisor to fixed paths (Node must be
installed system-wide on the service PATH, not in a home directory):

```sh
sudo useradd --system --home-dir /var/lib/lightning-driver --shell /usr/sbin/nologin lightning-driver
sudo install -d -m 0755 /opt/lightning-driver
sudo install -m 0755 target/release/api-server /opt/lightning-driver/api-server
sudo install -m 0644 deploy/server.mjs deploy/run.sh deploy/docker/config.localhost.toml /opt/lightning-driver/
sudo cp -R ui-build/dist /opt/lightning-driver/dist
sudo chmod -R a+rX /opt/lightning-driver/dist
sudo install -m 0644 deploy/standalone/lightning-driver.service /etc/systemd/system/lightning-driver.service
sudo systemctl daemon-reload
sudo systemctl enable --now lightning-driver.service
```

systemd creates `/var/lib/lightning-driver` owned by the dedicated user, mode
0700. The shared `deploy/run.sh` creates `config.toml` there on first start
only, then supervises API and UI; failure of either restarts the service.
Open **http://localhost:4400**, or forward that port over SSH for a remote host.
Both listeners are loopback-only. No node is needed for the shell to open.

To configure nodes, stop the service, edit `/var/lib/lightning-driver/config.toml`
using the root README's node examples, and place all credentials under that
directory, owned by `lightning-driver`, mode 0600. Remove `nodes = []` before
adding entries. Restart the service. Existing config is never overwritten.

```sh
sudo -u lightning-driver /opt/lightning-driver/api-server auth enrollment --config /var/lib/lightning-driver/config.toml
sudo journalctl -u lightning-driver.service -f
```

For a public domain, place a TLS reverse proxy on this host in front of
127.0.0.1:4400, preserving Host and Origin. Replace `api.public_origin` with
`https://your.exact.domain`, `api.rp_id` with `your.exact.domain`, and
`api.allow_insecure_loopback` with `false`. Keep the API bind unchanged.

For upgrades, stop the service, back up the **whole** state directory with
ownership and modes preserved (including invoice key and credentials), rebuild
as your user, replace the binary and `dist` (remove the old `dist` before
copying), and restart. Keep backups private and off-host. Never remove the
original invoice key or restore state into two running installations.
