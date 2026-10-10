# PostgreSQL TLS Configuration Guide

## Setup Steps

**Configure PostgreSQL:**

**Edit `/etc/postgresql/17/main/postgresql.conf`:**
```conf
ssl = on
ssl_cert_file = '/etc/ssl/certs/db.pem'
ssl_key_file = '/etc/ssl/private/db.key'
ssl_ca_file = '/etc/ssl/certs/ca.pem'
ssl_prefer_server_ciphers = on
ssl_ciphers = 'HIGH:!aNULL'

# look for listen_addresses and change the value to '*'
listen_addresses = '*'
```

**Edit `/etc/postgresql/17/main/pg_hba.conf`:**
```conf
# At the end of the file add this lines
hostssl  deathnode_db  app_worker      192.168.0.10/32         cert
hostssl  deathnode_db  shadow_admin    192.168.0.10/32         cert
```

# Firewall Rules

### Rules

- Default policy: DROP all incoming, forwarding and outgoing traffic.
- Allow loopback traffic (`lo`).
- Allow established/related connections to continue.
- Allow incoming TCP on port `5432` only from the server `192.168.0.10`.
- Allow ICMP (ping) from the server for basic network checks.
- Allow outgoing TCP/ICMP to the server `192.168.0.10`.
- Log blocked incoming packets with prefix `POSTGRES-BLOCKED:`.


## Run the Database

```bash
chmod +x init-db.sh
./init-db.sh
```