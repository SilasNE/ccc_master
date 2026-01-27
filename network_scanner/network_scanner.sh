#! /bin/bash

echo "==============="
echo "Network Scanner"
echo "==============="

# Netzwerk-Bereich eingeben
read -p "Gib das Netzwerk ein (z.B. 192.168.1.0/24): " network
echo "$network wird nach aktiven Hosts gescannt..."
nmap -sn $network

# IP für detaillierten Scan eingeben
read -p "Welche IP möchtest du davon genauer scannen? " target_ip
echo "$target_ip wird jetzt gescannt..."
nmap $target_ip

# Port-Scan optional
read -p "Möchtest du noch einen genaueren Port scannen? (J/N) " detailed
if [[ "$detailed" == "J" ]] || [[ "$detailed" == "j" ]]; then
    read -p "Welchen Port möchtest du scannen? " port
    echo "Port $port wird jetzt gescannt..."
    nmap -p $port $target_ip
    echo "Port $port wurde gescannt!"
else
    echo "Scan abgeschlossen."
fi
