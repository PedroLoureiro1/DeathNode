# Application Server

## Firewall

### Rules

- Default policy: DROP all incoming, forwarding and outgoing traffic.
- Allow loopback traffic (`lo`).
- Allow established/related connections to continue.
- Allow incoming TCP on port `5000` from vigilant Service (`192.168.100.1`) on the public interface `eth1`.
- Allow outgoing TCP to vigilant Service (`192.168.100.1`) on `eth1` only for established connections.
- Allow incoming TCP from PostgreSQL (`192.168.0.100`) on the internal interface `eth0` only for established connections.
- Allow outgoing TCP to PostgreSQL (`192.168.0.100`) port `5432` on the internal interface `eth0`.

## Run the server

```bash
# from the server directory
chmod +x init-server.sh
./init-server.sh
```


