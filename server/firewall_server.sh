#!/bin/bash

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -i lo -j ACCEPT

# Vigilant Service
iptables -A INPUT -s 192.168.100.1 -i eth1 -p tcp --dport 5000 -j ACCEPT
iptables -A OUTPUT -d 192.168.100.1 -o eth1 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT

# PostgresSQL
iptables -A INPUT -s 192.168.0.100 -i eth0 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -d 192.168.0.100 -o eth0 -p tcp --dport 5432 -j ACCEPT

iptables-save > /tmp/rules.v4
