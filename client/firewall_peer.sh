#!/bin/bash

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Vigilant Service
iptables -A INPUT -i eth0 -s 192.168.200.1 -m conntrack --ctstate ESTABLISHED -j ACCEPT