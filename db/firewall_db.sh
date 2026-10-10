#!/bin/bash

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -i lo -j ACCEPT

# --- ENTRY RULES ---
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -s 192.168.0.10 -p tcp --dport 5432 -j ACCEPT
iptables -A INPUT -s 192.168.0.10 -p icmp -j ACCEPT

# --- OUTPUT RULES ---
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d 192.168.0.10 -j ACCEPT
iptables -A OUTPUT -p icmp -d 192.168.0.10 -j ACCEPT

iptables -A INPUT -j LOG --log-prefix "POSTGRES-BLOCKED: "

iptables-save > /tmp/rules.v4
