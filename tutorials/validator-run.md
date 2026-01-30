# Nulla Validator: Run, Purge, and Systemd Service

This tutorial shows how to run a Nulla validator (relay) on Linux using a prebuilt `nulla-relay` binary and a chainspec from GitHub. It also covers how to purge the local chain data and how to run the node as a `systemd` service.

Assumptions
- OS: Ubuntu/Debian (adjust as needed)
- You have the `nulla-relay` binary (from GitHub releases or built locally)
- You have a Nulla chainspec JSON (from GitHub or this repo)
- Non-root user with `sudo`

---

## 1) Prepare Binary and Chainspec

Install the binary and set paths


Notes
- You can also point `--chain` directly to a raw chainspec path.
- If you have a raw spec, use that file instead of the JSON.

---

## 2) Run the Validator (Manual)

Basic run (local RPC only; adjust `--name` and ports)
```bash
/nulla-relay \
  --chain chainspec.json \
  --base-path /var/lib/nulla-relay \
  --validator \
  --name "YOUR_VALIDATOR_NAME" \
  --port <P2P PORT> \
  --rpc-port <RPC PORT> --rpc-external false \
```

Tips
- Keep RPC off the public internet; bind to localhost only.
- Session keys are required to author blocks; insert them via local RPC or tooling per Nulla docs.

---

## 3) Create a systemd Service

Create `/etc/systemd/system/nulla-relay.service`
```ini
[Unit]
Description=Nulla Relay Validator Node
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStart=/nulla-relay \
  --chain chainspec.json \
  --base-path /var/lib/nulla-relay \
  --validator \
  --name "YOUR_VALIDATOR_NAME" \
  --port <P2P PORT> \
  --rpc-port <RPC PORT> --rpc-external false \
Restart=always
RestartSec=10
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
```

Enable and start the service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nulla-relay.service
sudo systemctl status nulla-relay.service --no-pager
```

Logs and health
```bash
journalctl -u nulla-relay.service -f
ss -tulpen | grep -E ':30333|:9933'
```

---

## 4) Restarting and Updating

Restart the node
```bash
sudo systemctl restart nulla-relay.service
```

If the chainspec changes, replace it and restart
```bash
sudo cp new-chainspec.json chainspec.json
sudo systemctl restart nulla-relay.service
```


## 5) Purge Local Chain Data

Stop the node first (CTRL+C if running manually, or stop the service)
```bash
sudo systemctl stop nulla-relay || true
```

Purge the chain data (irreversible; re-sync required)
```bash
/nulla-relay purge-chain \
  --base-path /var/lib/nulla-relay \
  --chain chainspec.json \
  -y
```

Then start again to re-sync.

---


Notes
- Replace names/ports/paths for your environment.
- Validator key/session setup is separate; consult Nulla key management docs.
- For sentry topologies and security hardening, see the separate security guide.
