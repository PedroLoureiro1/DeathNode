# Client (Peer) Setup

## Setup Steps

Copy the peer certificate and key from the shared test secrets into the client VM. If you generated peers with `scripts/generate_test_certs.sh`, they are under `shared/test_secrets/peerN`.

```bash
cp ../shared/test_secrets/peer{number}/* certs/
```

## Firewall:

### Rules
- Default policy: DROP incoming and forwarding traffic, ACCEPT outgoing traffic.
- Allow loopback traffic (`lo`).
- Allow established/related connections to continue.
- Allow incoming TCP from vigilant Service (`192.168.200.1`) on `eth0` only for established connections.

## Run the client

```bash
chmod +x init-peer.sh
./init-peer.sh
```

