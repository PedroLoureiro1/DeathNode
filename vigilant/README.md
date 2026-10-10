# vigilant Setup

## Firewall

### Rules

- Default policy: DROP all incoming, forwarding and outgoing traffic.
- Allow loopback traffic (`lo`).
- Allow established/related connections to continue.
- Allow incoming TCP on port `6000` on the public interface `eth1`.
- Allow outgoing TCP on `eth1` only for established connections.
- Allow incoming TCP from Server (`192.168.100.2`) on the internal interface `eth0` only for established connections.
- Allow outgoing TCP to Server (`192.168.100.2`) port `5000` on the internal interface `eth0`.


## Run the vigilant

```bash
sudo chmod +x init-vigilant.sh
./init-vigilant
```

