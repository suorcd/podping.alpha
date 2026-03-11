# gossip-listener

A peer-to-peer subscriber that receives podcast feed update notifications over [Iroh](https://iroh.computer/) gossip. Part of the [Podping.alpha](../README.md) project.

## What it does

`gossip-listener` joins the `gossipping/v1/all` gossip topic, discovers peers via DHT and a local bootstrap list, and prints incoming `GossipNotification` messages to stdout. Each notification carries a list of podcast feed IRIs, a medium/reason classification, and an ed25519 signature that the listener verifies before display.

The listener also participates in the protocol's trust and discovery layers:

- **Peer discovery** -- saves `PeerAnnounce` and `NeighborUp` node IDs to a local file so future runs can bootstrap without DHT.
- **Trust propagation** -- accepts signed `PeerEndorse` messages from already-trusted senders and dynamically expands the trusted publisher set.
- **Watchdog** -- if no notification arrives within 180 seconds, automatically re-bootstraps from known peers.

## Building

### With Nix

```sh
nix build .#gossip-listener
./result/bin/gossip-listener
```

Or run directly:

```sh
nix run
```

### With Cargo

```sh
cargo build --release --manifest-path gossip-listener/Cargo.toml
./gossip-listener/target/release/gossip-listener
```

### With prebuilt binaries (GitHub Releases)

When you tag a release (e.g., `v1.2.3`), the GitHub Action publishes binaries
for Linux, macOS, and Windows under the release assets.

Download and verify:

```sh
VERSION="v1.2.3"
OS=linux # linux | macos | windows
ARCH=x86_64 # x86_64 | aarch64
URL="https://github.com/<owner>/<repo>/releases/download/${VERSION}/gossip-listener-${VERSION}-${OS}-${ARCH}.tar.gz"
SHA_URL="${URL}.sha256"
curl -L "$URL" -o gossip-listener.tar.gz
curl -L "$SHA_URL" -o gossip-listener.tar.gz.sha256
shasum -a 256 -c gossip-listener.tar.gz.sha256
tar -xzf gossip-listener.tar.gz
./gossip-listener
```

Windows (PowerShell):

```powershell
$Version = "v1.2.3"
$Url = "https://github.com/<owner>/<repo>/releases/download/$Version/gossip-listener-$Version-windows-x86_64.zip"
$ShaUrl = "$Url.sha256"
Invoke-WebRequest -Uri $Url -OutFile gossip-listener.zip
Invoke-WebRequest -Uri $ShaUrl -OutFile gossip-listener.zip.sha256
$Expected = (Get-Content gossip-listener.zip.sha256).Split(' ')[0].ToLower()
$Actual = (Get-FileHash -Algorithm SHA256 -Path gossip-listener.zip).Hash.ToLower()
if ($Expected -ne $Actual) { throw "SHA256 mismatch" }
Expand-Archive -Path gossip-listener.zip -DestinationPath .
./gossip-listener.exe
```

### With Docker

Build locally from this repo:

```sh
docker build -f docker/Dockerfile.gossip-listener -t gossip-listener:local .
docker run --rm -it \
  -v "$(pwd)":/data \
  gossip-listener:local
```

Pull the published image from GHCR:

```sh
docker pull ghcr.io/<owner>/gossip-listener:latest
docker run --rm -it \
  -v "$(pwd)":/data \
  ghcr.io/<owner>/gossip-listener:latest
```

The container runs as a non-root user (UID 1000) with `/data` as the working
directory, so mount a writable volume if you want to persist node keys and
known peers.

### With Docker Compose

Use the dedicated compose file:

```sh
docker compose -f docker/docker-compose.gossip-listener.yaml up -d
```

Data is stored under `./data/gossip-listener` by default, and the compose file
sets the `*_FILE` environment variables to `/data/...` paths for persistence.

## Configuration

All configuration is via environment variables. Every variable is optional.

| Variable | Default | Description |
|---|---|---|
| `BOOTSTRAP_PEER_IDS` | *(empty)* | Comma-separated Iroh node IDs to join on startup |
| `IROH_NODE_KEY_FILE` | `gossip_listener_node.key` | Path to persistent node identity key |
| `KNOWN_PEERS_FILE` | `gossip_listener_known_peers.txt` | Path to read/write discovered peer IDs (max 15) |
| `DHT_INITIAL_SECRET` | `podping_gossip_default_secret` | Shared secret for DHT auto-discovery |
| `TRUSTED_PUBLISHERS_FILE` | `trusted_publishers.txt` | Path to a file of trusted ed25519 public keys (hex, one per line). Empty = accept all |
| `PEER_ANNOUNCE_INTERVAL` | `300` | Seconds between broadcasting `PeerAnnounce` messages |
| `PEER_ENDORSE_INTERVAL` | `45` | Seconds between broadcasting `PeerEndorse` messages |

## Output format

Verified notifications are printed as single-line JSON prefixed with `PODPING:`:

```
PODPING: [{"version":"1.1","sender":"ab12...","timestamp":1709827200,"medium":"podcast","reason":"update","iris":["https://example.com/feed.xml"],"signature":"cd34...","sig_status":"VALID"}]
```

The `sig_status` field is one of `VALID`, `UNSIGNED`, or `INVALID`.

## Trusted publisher filtering

If `trusted_publishers.txt` (or the path set by `TRUSTED_PUBLISHERS_FILE`) contains one or more hex-encoded ed25519 public keys, only notifications from those senders are displayed. The set can grow at runtime when a trusted peer broadcasts a signed `PeerEndorse` message vouching for additional keys.

If the file is empty or missing, all notifications are accepted.

## License

[MIT](../LICENSE)
